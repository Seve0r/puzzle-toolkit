#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
编码 / 解码万用工具。纯标准库，无外部依赖。

子命令：
  auto   <text>        自动识别编码并递归剥皮，输出最可能的明文
  brute  <text>        把每一种编码都试一遍，列出所有可读结果
  dec    <enc> <text>  用指定编码解码
  enc    <enc> <text>  用指定编码编码
  list                 列出所有支持的编码名
  grid   <text>        切矩阵枚举读法（行/列/蛇形/反转），--rows --cols --width
  blocks <text>        定长块按进制转字节，-w 块宽 -r 进制（如 -w 2 -r 36）

通用选项：
  -f, --file <path>    从文件读输入（二进制安全，配合 enc hex/base64 很有用）
  -q, --quiet          只输出结果，不要解释
  --depth N            auto 的递归深度（默认 3）
  --best               配合 dec mojibake：数据残缺时强制输出最佳猜测，缺失处标 ?
  --deep [N]           配合 dec mojibake：反复还原直到正常文字占比 >= N%
                       （0~100，默认 50）。多层乱码一步到位，并列出每层可读率。
  --from <enc>         配合 dec mojibake：指定当初「把字节解成乱码」用的编码
  --to <enc>           配合 dec mojibake：指定当初「把文字编成字节」用的编码
                       两个都不用猜；只给一个时另一个取默认（gb18030 / utf-8）。

例：
  codec.py auto 'S1VWRVIgTEFOR1VBR0U='
  codec.py brute '&#x4f60;&#x597d;'
  codec.py dec base58 '2NEpo7TZRRrLZSi2U'
  codec.py enc hex --file /bin/ls | head
  codec.py dec mojibake '浜哄彧鑳界湅'
  codec.py dec mojibake --best '瀹跺涵鐘跺喌'
  codec.py dec mojibake --deep 80 --file cipher.txt
  codec.py dec mojibake '孨偼堦惗巹傪朰傟側偄'          # 自动认出 GBK→Shift_JIS
  codec.py dec mojibake --from gbk --to shift_jis '孨偼堦惗巹傪朰傟側偄'
"""
import sys
import os
import re
import math
import base64
import binascii
import codecs
import hashlib
import zlib
import bz2
import gzip
import html
import urllib.parse
import io
import json
import unicodedata

# ---------------------------------------------------------------- 注册表

ENCODERS = {}
DECODERS = {}


def enc_name(*names):
    def wrap(fn):
        for n in names:
            ENCODERS[n] = fn
        return fn
    return wrap


def dec_name(*names):
    def wrap(fn):
        for n in names:
            DECODERS[n] = fn
        return fn
    return wrap


def as_bytes(s):
    return s.encode("utf-8", "surrogateescape") if isinstance(s, str) else s


def raw_bytes(s):
    """把「用 latin-1 承载的原始字节」还原成 bytes。

    CLI 从命令行或文本文件拿到的是 str，但压缩流 / UTF-16 这类输入本质上是
    二进制，通常被 1 字符 = 1 字节地保存（latin-1 视角）。

    直接 as_bytes() 会按 UTF-8 重新编码，把 `0xFF` 变成 `C3 BF`——
    UTF-16 的 BOM `FF FE` 因此变成 `C3 BF C3 BE`，BOM 检测永远失败，
    报「没有 BOM，不能确定字节序」。压缩流也会因为魔数被改写而全部解不开。

    判断方式：所有码点都 < 256 就按 latin-1 还原，否则说明确实是 Unicode
    文本，走 as_bytes。
    """
    if isinstance(s, str) and all(ord(c) < 256 for c in s):
        return s.encode("latin-1")
    return as_bytes(s)


def as_text(b):
    return b.decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) else b


# ---------------------------------------------------------------- Base 系列

@dec_name("base64", "b64")
def _d_b64(s):
    s = re.sub(r"\s+", "", s)
    s += "=" * (-len(s) % 4)
    return as_text(base64.b64decode(s, validate=False))


@enc_name("base64", "b64")
def _e_b64(s):
    return base64.b64encode(as_bytes(s)).decode()


@dec_name("base64url", "b64url")
def _d_b64url(s):
    s = re.sub(r"\s+", "", s)
    s += "=" * (-len(s) % 4)
    return as_text(base64.urlsafe_b64decode(s))


@enc_name("base64url", "b64url")
def _e_b64url(s):
    return base64.urlsafe_b64encode(as_bytes(s)).decode()


@dec_name("base32", "b32")
def _d_b32(s):
    s = re.sub(r"\s+", "", s).upper()
    s += "=" * (-len(s) % 8)
    return as_text(base64.b32decode(s))


@enc_name("base32", "b32")
def _e_b32(s):
    return base64.b32encode(as_bytes(s)).decode()


@dec_name("base32hex", "b32hex")
def _d_b32hex(s):
    s = re.sub(r"\s+", "", s).upper()
    s += "=" * (-len(s) % 8)
    return as_text(base64.b32hexdecode(s))


@dec_name("base16", "hex")
def _d_hex(s):
    s = re.sub(r"(0x|\\x|[\s:,])", "", s)
    if len(s) % 2:
        s = "0" + s
    return as_text(binascii.unhexlify(s))


@enc_name("base16", "hex")
def _e_hex(s):
    return as_bytes(s).hex()


B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dec_name("base58", "b58", "base58btc")
def _d_b58(s):
    n = 0
    for ch in s:
        n = n * 58 + B58_ALPHABET.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return as_text(b"\x00" * pad + raw)


@enc_name("base58", "b58", "base58btc")
def _e_b58(s):
    b = as_bytes(s)
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


B62_SETS = ["0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]


@dec_name("base62", "b62")
def _d_b62(s):
    # 三种常见字母表都试，取第一个能解出可打印 ASCII 的
    best = None
    for alpha in B62_SETS:
        try:
            n = 0
            for ch in s:
                n = n * 62 + alpha.index(ch)
            raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
            txt = raw.decode("utf-8", "replace")
            if best is None or score(txt) > score(best):
                best = txt
        except Exception:
            continue
    if best is None:
        raise ValueError("不是合法 base62")
    return best


@dec_name("base85", "b85")
def _d_b85(s):
    return as_text(base64.b85decode(s))


@enc_name("base85", "b85")
def _e_b85(s):
    return base64.b85encode(as_bytes(s)).decode()


@dec_name("ascii85", "a85")
def _d_a85(s):
    s = s.strip()
    if s.startswith("<~") and s.endswith("~>"):
        s = s[2:-2]
    return as_text(base64.a85decode(s))


B91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
       "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")


@dec_name("base91", "b91")
def _d_b91(s):
    v = -1
    b = 0
    n = 0
    out = bytearray()
    for ch in s:
        c = B91.find(ch)
        if c < 0:
            continue
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return as_text(bytes(out))


@dec_name("base36", "b36")
def _d_b36(s):
    t = re.sub(r"\s+", "", s).upper()
    n = 0
    for ch in t:
        n = n * 36 + "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".index(ch)
    return as_text(n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")


@enc_name("base36", "b36")
def _e_b36(s):
    n = int.from_bytes(as_bytes(s), "big")
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[r] + out
    return out or "0"


# ---------------------------------------------------------------- 进制 / 二进制串

@dec_name("bin", "binary")
def _d_bin(s):
    bits = re.sub(r"[^01]", "", s)
    if len(bits) % 8:
        raise ValueError("二进制位数不是 8 的倍数")
    return as_text(bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)))


@enc_name("bin", "binary")
def _e_bin(s):
    return " ".join(format(b, "08b") for b in as_bytes(s))


@dec_name("dec", "decimal")
def _d_dec(s):
    nums = [int(x) for x in re.findall(r"\d+", s)]
    if not nums:
        raise ValueError("没有数字")
    if max(nums) > 255:
        raise ValueError("数值超出字节范围")
    return as_text(bytes(nums))


@enc_name("dec", "decimal")
def _e_dec(s):
    return " ".join(str(b) for b in as_bytes(s))


@dec_name("oct", "octal")
def _d_oct(s):
    nums = [int(x, 8) for x in re.findall(r"[0-7]+", s)]
    if not nums or max(nums) > 255:
        raise ValueError("不是合法八进制")
    return as_text(bytes(nums))


@enc_name("oct", "octal")
def _e_oct(s):
    return " ".join(format(b, "o") for b in as_bytes(s))


# ---------------------------------------------------------------- Punycode

# 把非 ASCII 文本塞进纯 ASCII 域名的编码，IDN（如 .jp 的日文域名）就用它，
# 形式上固定带 `xn--` 前缀。属于「可逆编码」，性质接近 Base64 而不是加密。
#
# ★ 不能用 idna codec 解：idna 会当完整域名来校验，带逗号、空格的谜题数据
#   一律报错。必须剥掉前缀后直接走 punycode codec。
# ★ 以 xn-- 开头的串长度常是 4 的倍数、字符集又落在 base64url 里（- 合法），
#   所以结构识别必须排在 base64url 前面，否则会被它抢走。
_PUNY_SEP = re.compile(r"[.\s]+")
_PUNY_PREFIX = re.compile(r"^xn--", re.IGNORECASE)


@dec_name("punycode", "puny", "idn")
def _d_punycode(s):
    raw = s.strip()
    parts = [p for p in _PUNY_SEP.split(raw) if p]
    if not parts:
        raise ValueError("空输入")
    out = []
    for p in parts:
        body = _PUNY_PREFIX.sub("", p)
        # 没有 xn-- 前缀、整段又是纯 ASCII：编码方向不会改动它（IDNA 也是
        # 这个规则），解码就原样返回。否则 "hello world" 这种普通英文会被
        # 当成 punycode 硬解，抛 UnicodeError("incomplete punicode string")，
        # enc/dec 往返就不自洽了。
        if body == p and p.isascii():
            out.append(p)
            continue
        out.append(body.encode("ascii").decode("punycode"))
    if "." in raw:
        return ".".join(out)        # 域名形式：按标签还原成点分
    if len(out) > 1:
        return "\n".join(out)       # 多行/多段：一段一行，别粘成一坨
    return out[0]


@enc_name("punycode", "puny", "idn")
def _e_punycode(s):
    out = []
    for ln in [x for x in s.splitlines() if x.strip()]:
        # 纯 ASCII 的行不需要编码（IDNA 也是这个规则），原样保留更好读
        out.append(ln if ln.isascii()
                   else "xn--" + ln.encode("punycode").decode("ascii"))
    if not out:
        raise ValueError("空输入")
    return "\n".join(out)


# ---------------------------------------------------------------- 转义类

@dec_name("url", "urlenc", "percent")
def _d_url(s):
    return urllib.parse.unquote(s)


@enc_name("url", "urlenc", "percent")
def _e_url(s):
    return urllib.parse.quote(s)


@dec_name("html", "htmlent", "entity")
def _d_html(s):
    return html.unescape(s)


@enc_name("html", "htmlent", "entity")
def _e_html(s):
    return "".join("&#x%x;" % ord(c) if ord(c) > 127 else c for c in s)


@dec_name("unicode", "uescape", "\\u")
def _d_unicode(s):
    # ① \xNN 连续串：先聚成 bytes 再按 UTF-8 解。
    #    \xe4\xbd\xa0 是「你」的 UTF-8 三字节 —— 逐字节 chr() 只会得到 ä½。
    def hex_run(m):
        raw = m.group(0)
        bs = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", raw))
        try:
            return bs.decode("utf-8")
        except UnicodeDecodeError:
            return bs.decode("latin-1")
    s = re.sub(r"(?:\\x[0-9a-fA-F]{2})+", hex_run, s)

    # ② \u{1F600}（JS/现代写法）、\uXXXX、\UXXXXXXXX
    s = re.sub(r"\\u\{([0-9a-fA-F]{1,6})\}", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"\\U([0-9a-fA-F]{8})", lambda m: chr(int(m.group(1), 16)), s)

    # ③ 合并孤立代理对：\ud83d\ude00 是两个 surrogate，拼起来才是 😀
    try:
        s = s.encode("utf-16", "surrogatepass").decode("utf-16")
    except UnicodeError:
        pass

    # ④ U+4F60 这种标准写法，以及老式 IIS 的 %u4F60
    s = re.sub(r"U\+([0-9a-fA-F]{4,6})", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    return s


@enc_name("unicode", "uescape", "\\u")
def _e_unicode(s):
    return "".join("\\u%04x" % ord(c) if ord(c) > 127 else c for c in s)


@dec_name("js", "jsescape")
def _d_js(s):
    return _d_unicode(s)


@dec_name("qp", "quotedprintable")
def _d_qp(s):
    import quopri
    return as_text(quopri.decodestring(s))


@enc_name("qp", "quotedprintable")
def _e_qp(s):
    import quopri
    return as_text(quopri.encodestring(as_bytes(s)))


def _rot_n(s, n):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


@dec_name("rot13")
def _d_rot13(s):
    return _rot_n(s, 13)


@enc_name("rot13")
def _e_rot13(s):
    return _rot_n(s, 13)


@dec_name("rot47")
def _d_rot47(s):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)


@dec_name("atbash")
def _d_atbash(s):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr(122 - (ord(c) - 97)))
        elif "A" <= c <= "Z":
            out.append(chr(90 - (ord(c) - 65)))
        else:
            out.append(c)
    return "".join(out)


# ---------------------------------------------------------------- 摩斯

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", ".----.": "'", "-.-.--": "!",
    "-..-.": "/", "-.--.": "(", "-.--.-": ")", ".-...": "&", "---...": ":",
    "-.-.-.": ";", "-...-": "=", ".-.-.": "+", "-....-": "-", "..--.-": "_",
    ".-..-.": '"', "...-..-": "$", ".--.-.": "@",
}

MORSE_REV = {v: k for k, v in MORSE.items()}


@dec_name("morse", "morsecode")
def _d_morse(s):
    t = (s.replace("·", ".").replace("•", ".").replace("—", "-")
          .replace("–", "-").replace("−", "-").replace("_", "-"))
    # 三种分隔：/ 是词，多空格是词，单空格是字母
    if "/" in t:
        words = t.split("/")
        sep = " "
    elif re.search(r"\s{2,}|\n", t.strip()):
        words = re.split(r"\s{2,}|\n", t.strip())
        sep = " "
    else:
        words = [t]
        sep = " "
    out = []
    for w in words:
        letters = [MORSE.get(c, "?") for c in w.split(sep) if c]
        out.append("".join(letters))
    return " ".join(out).strip()


@enc_name("morse", "morsecode")
def _e_morse(s):
    words = []
    for w in s.upper().split():
        words.append(" ".join(MORSE_REV.get(c, "") for c in w))
    return " / ".join(words)


# ------------------------------------------------- 和文モールス（Wabun code）

# 与国际摩斯是**两套完全不同的体系**：同样的符号在两张表里代表不同字符，
# 所以不能共用一个解码器。表源：無線局運用規則 別表第一号（総務省）。
#
# ★ 这张表里有同码：ト 与 ウ 都是 `..-`，ル 与「（」都是 `-.--.`。
#   光看符号永远定不下来，只能靠上下文。所以解码时同码位置输出 `{A|B}`，
#   把选择权交回给人——静默返回第一个候选会给出「语法通顺但意思全错」的
#   答案。实测踩过：`..-` 取 ト 得「じんことのかみ」，取 ウ 得
#   「じんこうのかみ」(人工の神)，两者日语都通顺，但只有后者对得上剧情。
WABUN = {
    "ア": "--.--", "イ": ".-", "ウ": "..-", "エ": "-.---", "オ": ".-...",
    "カ": ".-..", "キ": "-..-..", "ク": "...-", "ケ": "-.--", "コ": "----",
    "サ": "-.-.-", "シ": "--.-.", "ス": "---.-", "セ": ".---.", "ソ": "---.",
    "タ": "-.", "チ": "..-.", "ツ": ".--.", "テ": ".-.--", "ト": "..-",
    "ナ": ".-.", "ニ": "-.-.", "ヌ": "....", "ネ": "--.-", "ノ": "..--",
    "ハ": "-...", "ヒ": "--..-", "フ": "--..", "ヘ": ".", "ホ": "-..",
    "マ": "-..-", "ミ": "..-.-", "ム": "-", "メ": "-...-", "モ": "-..-.",
    "ヤ": ".--", "ユ": "-..--", "ヨ": "--",
    "ラ": "...", "リ": "--.", "ル": "-.--.", "レ": "---", "ロ": ".-.-",
    "ワ": "-.-", "ヰ": ".-..-", "ヱ": ".--..", "ヲ": ".---", "ン": ".-.-.",
    "゛": "..", "゜": "..--.", "ー": ".--.-",
    "、": ".-.-.-", "（": "-.--.", "）": ".-..-.",
}

WABUN_REV = {}
for _k, _v in WABUN.items():
    WABUN_REV.setdefault(_v, []).append(_k)

# 浊音/半浊音在摩斯里是独立符号（゛/゜），解码后要粘回前一个假名。
# 和文モールス正是靠这个机制表达的，所以没有单独的清音→浊音编码。
_WABUN_DAKU = {
    "カ": "ガ", "キ": "ギ", "ク": "グ", "ケ": "ゲ", "コ": "ゴ",
    "サ": "ザ", "シ": "ジ", "ス": "ズ", "セ": "ゼ", "ソ": "ゾ",
    "タ": "ダ", "チ": "ヂ", "ツ": "ヅ", "テ": "デ", "ト": "ド",
    "ハ": "バ", "ヒ": "ビ", "フ": "ブ", "ヘ": "ベ", "ホ": "ボ",
}
_WABUN_HANDAKU = {"ハ": "パ", "ヒ": "ピ", "フ": "プ", "ヘ": "ペ", "ホ": "ポ"}


def _wabun_near(a, b, maxd=1):
    """编辑距离 <= maxd。只用来给「查不到的段」提示最接近的几个候选。"""
    if abs(len(a) - len(b)) > maxd:
        return False
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (a[i - 1] != b[j - 1]))
        prev = cur
    return prev[len(b)] <= maxd


@dec_name("wabun", "wabunmorse")
def _d_wabun(s):
    t = (s.replace("·", ".").replace("•", ".").replace("・", ".")
          .replace("—", "-").replace("－", "-").replace("–", "-")
          .replace("−", "-").replace("_", "-"))
    segs = [x for x in re.split(r"[/\s]+", t.strip()) if x]
    if not segs:
        raise ValueError("空输入")
    out = []
    unknown = []
    for idx, seg in enumerate(segs, 1):
        cands = WABUN_REV.get(seg)
        if not cands:
            out.append("?")                 # 表里没有这个码
            unknown.append((idx, seg))
        elif len(cands) == 1:
            out.append(cands[0])
        else:
            out.append("{%s}" % "|".join(cands))   # 同码：全部列出，不替人做决定
    # 浊音符号粘回前一个假名；前一个若是 {A|B} 歧义组则原样保留，不硬合并
    merged = []
    for c in out:
        if c == "゛" and merged and merged[-1] in _WABUN_DAKU:
            merged[-1] = _WABUN_DAKU[merged[-1]]
        elif c == "゜" and merged and merged[-1] in _WABUN_HANDAKU:
            merged[-1] = _WABUN_HANDAKU[merged[-1]]
        else:
            merged.append(c)
    # 光在结果里打个 `?` 没用：几十个词里有一个坏点，人得逐段比对才知道是哪。
    # 把查不到的段连同序号一起写到 stderr，命令行重定向时结果依然干净。
    if unknown:
        sys.stderr.write(
            "\n  [!] 有 %d 段在和文モールス表里查不到（多半是抄写错误）：\n"
            % len(unknown))
        for idx, seg in unknown:
            near = [k for k, v in WABUN.items() if _wabun_near(seg, v)]
            hint = ("；相近的有 " + " / ".join("%s=%s" % (k, WABUN[k]) for k in near[:3])) if near else ""
            sys.stderr.write("      第 %d 段  %s%s\n" % (idx, seg, hint))
        sys.stderr.write("\n")
    return "".join(merged)


# ---------------------------------------------------------------- 盲文

BRAILLE_BASE = 0x2800
BRAILLE_EN = {
    "a": 0x01, "b": 0x03, "c": 0x09, "d": 0x19, "e": 0x11, "f": 0x0B,
    "g": 0x1B, "h": 0x13, "i": 0x0A, "j": 0x1A, "k": 0x05, "l": 0x07,
    "m": 0x0D, "n": 0x1D, "o": 0x15, "p": 0x0F, "q": 0x1F, "r": 0x17,
    "s": 0x0E, "t": 0x1E, "u": 0x25, "v": 0x27, "w": 0x3A, "x": 0x2D,
    "y": 0x3D, "z": 0x35, " ": 0x00,
}
BRAILLE_EN_REV = {v: k for k, v in BRAILLE_EN.items()}
DIGIT_SIGN = 0x3C
CAPITAL_SIGN = 0x20


@dec_name("braille")
def _d_braille(s):
    """两种输出：英文（带数字/大写符号处理）和 8 位点阵原始位串"""
    chars = [c for c in s if BRAILLE_BASE <= ord(c) <= BRAILLE_BASE + 0xFF]
    if not chars:
        raise ValueError("没有盲文字符")
    out = []
    numeric = False
    caps = False
    for c in chars:
        v = ord(c) - BRAILLE_BASE
        if v == DIGIT_SIGN:
            numeric = True
            continue
        if v == CAPITAL_SIGN:
            caps = True
            continue
        if v == 0x00:
            out.append(" ")
            numeric = False          # 空格结束数字模式
            continue
        if numeric and v in BRAILLE_EN_REV:
            letter = BRAILLE_EN_REV[v]
            if letter in "abcdefghij":
                # 盲文数字：a-j -> 1-9,0。
                # 早期版本写成 "abcdefghij"[ord(letter)-97]，恒等于 letter 本身，
                # 等于数字模式从来没真正生效过——数字全被当成字母输出了。
                out.append("1234567890"[ord(letter) - 97])
                continue
            numeric = False          # 不是 a-j，数字模式到此结束
        ch = BRAILLE_EN_REV.get(v, "?")
        out.append(ch.upper() if caps else ch)
        caps = False
    return "".join(out)


@dec_name("braillebits")
def _d_braillebits(s):
    """8 点盲文 → 点 1..8 的二进制串（每字符一行），用于自定义点阵解码"""
    rows = []
    for c in s:
        if not (BRAILLE_BASE <= ord(c) <= BRAILLE_BASE + 0xFF):
            continue
        v = ord(c) - BRAILLE_BASE
        bits = "".join("1" if v & (1 << i) else "0" for i in range(8))
        rows.append(bits)
    if not rows:
        raise ValueError("没有盲文字符")
    # 同时给出两个转置视图，方便按点通道读
    horizontal = "".join(rows)
    vertical = "".join("".join(r[i] for r in rows) for i in range(8))
    return json.dumps({
        "per_char": rows,
        "bits_concat": horizontal,
        "bits_by_dot": vertical,
        "count": len(rows),
    }, ensure_ascii=False)


@enc_name("braille")
def _e_braille(s):
    out = []
    for c in s.lower():
        if c in BRAILLE_EN:
            out.append(chr(BRAILLE_BASE + BRAILLE_EN[c]))
        elif c.isdigit():
            out.append(chr(BRAILLE_BASE + DIGIT_SIGN))
            out.append(chr(BRAILLE_BASE + BRAILLE_EN["abcdefghij"[int(c)]]))
        else:
            out.append(c)
    return "".join(out)


# ---------------------------------------------------------------- 压缩流 / 其他

@dec_name("gzip", "zlib", "bz2", "deflate", "inflate")
def _d_compress(s):
    raw = raw_bytes(s)
    for fn in (lambda b: gzip.decompress(b),
               zlib.decompress,
               lambda b: zlib.decompress(b, -15),
               bz2.decompress):
        try:
            return as_text(fn(raw))
        except Exception:
            continue
    raise ValueError("解压失败")


@dec_name("uu")
def _d_uu(s):
    # uuencode 的完整结构是：
    #   begin 644 文件名
    #   <数据行>
    #   `            ← 长度 0 的行，表示结束
    #   end
    # 早期实现直接拿第一行去 a2b_uu，而那是 begin 头，永远报 Illegal char——
    # 等于标准格式的 uuencode 一律解不出来。这里按结构逐行解，
    # 同时兼容「只有裸数据行、没有 begin/end 包裹」的输入。
    out = []
    body = False
    for ln in s.splitlines():
        if ln.startswith("begin "):
            body = True
            continue
        if ln.strip() == "end" or ln.startswith("`"):
            break
        if not ln.strip():
            continue
        body = True
        try:
            out.append(binascii.a2b_uu(ln))
        except binascii.Error as e:
            raise ValueError("uuencode 数据行解析失败：%s" % e)
    if not out:
        raise ValueError("没有可解码的 uuencode 数据")
    return as_text(b"".join(out))


@dec_name("utf16")
def _d_utf16(s):
    raw = raw_bytes(s)
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    raise ValueError("没有 BOM，不能确定字节序")


@dec_name("utf16be")
def _d_utf16be(s):
    raw = raw_bytes(s)
    return raw.decode("utf-16-be")


@dec_name("utf16le")
def _d_utf16le(s):
    raw = raw_bytes(s)
    return raw.decode("utf-16-le")


# ---- UTF-32：每码点 4 字节。CTF 里常见形态是「每码点 8 位 hex」：
#      00000023 = '#'、00007ED9 = '给'、00004E86 = '了'
#      判别要点：hex 长度是 8 的倍数，且多数码点带大片前导零。
def _u32_input(s):
    """UTF-32 的输入可能是 hex 串，也可能已是裸字节。"""
    t = re.sub(r"\s+", "", s)
    if len(t) >= 8 and len(t) % 8 == 0 and re.fullmatch(r"[0-9a-fA-F]+", t):
        return bytes.fromhex(t)
    return raw_bytes(s)


@dec_name("utf32")
def _d_utf32(s):
    raw = _u32_input(s)
    if raw[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return raw.decode("utf-32")
    if len(raw) % 4:
        raise ValueError("UTF-32 要求字节数是 4 的倍数")
    head = raw[:4]
    # 无 BOM：看首个码点的前导零分布猜字节序
    if head[0] == 0 and head[1] == 0 and head[2] == 0:
        return raw.decode("utf-32-be")
    if head[1] == 0 and head[2] == 0 and head[3] == 0:
        return raw.decode("utf-32-le")
    raise ValueError("没有 BOM 且猜不出字节序，请显式用 utf32be / utf32le")


@dec_name("utf32be")
def _d_utf32be(s):
    return _u32_input(s).decode("utf-32-be")


@dec_name("utf32le")
def _d_utf32le(s):
    return _u32_input(s).decode("utf-32-le")


@enc_name("utf32be")
def _e_utf32be(s):
    # 输出 8 位一组的 hex，和出题人常见写法一致
    return as_bytes(s).decode("utf-8", "replace").encode("utf-32-be").hex()


@enc_name("utf32le")
def _e_utf32le(s):
    return as_bytes(s).decode("utf-8", "replace").encode("utf-32-le").hex()


@dec_name("gbk")
def _d_gbk(s):
    return as_bytes(s).decode("gbk")


@enc_name("gbk")
def _e_gbk(s):
    return as_bytes(s).decode("gbk", "replace")


# 顺序有讲究：cp932 放在 shift_jis 前面，因为 cp932（Windows-31J）是
# Shift_JIS 的超集，能覆盖 ㈹ / 半角片假名这类「机种依存文字」，
# 而严格的 shift_jis 遇到它们会直接 encode 失败、整个假设被跳过。
MOJIBAKE_ENCODINGS = [
    "gb18030", "gbk",
    "cp932", "shift_jis", "shift_jis_2004", "shift_jisx0213",
    "big5", "euc-kr",
    "latin-1", "cp1252", "cp1251", "iso-8859-2",
]


# CP936 把单字节 0x80 定义成欧元符号 €，但 Python 的 gbk/gb18030 codec 不认
# 这个单字节（gb18030 反而把 U+20AC 编成双字节 A2E3）。乱码里一旦出现 €，
# 多出来的那个字节会让它之后整行错位一格：本来能无损伤还原的内容会变成
# 「丢?个亲生孩子」这种鬼样子，还会把损失率抬上去、把正确假设挤掉。
# 所以 GBK 系回编码时必须手动把 € 还原成 0x80。
_GBK_FAMILY = {"gb18030", "gbk"}


# 「目标编码」= 当初把原始字节解成这堆乱码时用的那个编码。
# mojibake_rank 只假设目标是 UTF-8（最常见），但中日韩编码之间互相误读
# 同样常见，而且**这种乱码用 UTF-8 是解不出来的**——必须换目标。
#
# 实测：孨偼堦惗巹傪朰傟側偄 按 GBK 编回字节再按 Shift_JIS 解 = 君は一生私を忘れない。
# 按 UTF-8 解则损失 60%，而且报错还会误导成「数据损坏」。
#
# 不含 utf-16/utf-32：它们只要字节数是偶数就几乎总能「成功」，产出一堆
# 私用区字符却报 0 损失，是纯粹的假阳性来源。
MOJIBAKE_TARGETS = [
    "gb18030", "gbk",
    "big5",
    "cp932", "shift_jis", "shift_jis_2004", "shift_jisx0213",
    "euc-kr", "euc-jp", "iso2022_jp",
    "latin-1", "cp1252",
]

# 同族编码互相转码是恒等变换（gb18030 是 gbk 的超集，cp932 是 shift_jis 的
# 超集），「按 A 编回字节再按 B 解」得到的还是原文自己。不排除的话它们会以
# 0% 损失永远霸占第一名，把真正有用的假设全挤掉。
_MOJIBAKE_FAMILIES = [
    {"gb18030", "gbk"},
    {"cp932", "shift_jis", "shift_jis_2004", "shift_jisx0213"},
    {"latin-1", "cp1252"},
    {"cp1251", "iso-8859-2"},
]


def _same_encoding_family(a, b):
    """a、b 是否属于同一个编码族（互相转码等于没转）。"""
    if a == b:
        return True
    return any(a in fam and b in fam for fam in _MOJIBAKE_FAMILIES)


def _encode_back(s, enc):
    """把乱码字符串按 enc 还原成原始字节（含 CP936 的 0x80 ↔ € 特例）。"""
    if enc not in _GBK_FAMILY or "\u20ac" not in s:
        return s.encode(enc)
    out = bytearray()
    for ch in s:
        if ch == "\u20ac":
            out.append(0x80)
        else:
            out += ch.encode(enc)
    return bytes(out)


def mojibake_rank(s):
    """枚举「UTF-8 被误读成别的编码」的所有可能，按 U+FFFD 损失率排序。

    原理：把当前字符串按候选编码**反向编码回字节**，再按 UTF-8 解开。
    猜中当初的误读方式时，拿回的正是原始 UTF-8 字节，解码无损；
    猜错时字节流不合法，会碎成一堆 U+FFFD。所以损失率最低 = 最可能。

    返回 [(损失率, 替换字符数, 编码名, 还原结果), ...]，已排序。
    """
    rows = []
    for enc in MOJIBAKE_ENCODINGS:
        try:
            raw = _encode_back(s, enc)   # 严格：不在该编码里的字符直接判该假设失败
        except (UnicodeEncodeError, LookupError):
            continue
        out = raw.decode("utf-8", errors="replace")
        bad = out.count("\ufffd")
        rows.append((bad / max(1, len(out)), bad, enc, out))
    rows.sort()
    return rows


_ENC_CACHE = {}


def _encodable(ch, enc):
    """该字符能否用 enc 表示。带缓存——_plain 会被反复调用，试编很贵。"""
    key = (ch, enc)
    hit = _ENC_CACHE.get(key)
    if hit is None:
        try:
            ch.encode(enc)
            hit = True
        except Exception:
            hit = False
        _ENC_CACHE[key] = hit
    return hit


def _plain(s):
    """「像不像正常文字」0~1。用来在跨编码还原的多个候选中挑出真结果。

    只看字符落点，不看语义：
      加分：GB2312 内的常用汉字、平假名/片假名、ASCII、谚文
      减分：私用区、U+FFFD、控制符、C1、西里尔/希腊、拉丁扩展、杂项文字

    ★ 汉字分「GB2312 内 / 外」两种待遇，这是判据的核心：中文乱码的产物
      是 孨偼堦惗巹傪 这类 GB2312 之外的生僻字，正常文本则几乎全在里面。
      实测：孨偼堦惗巹傪朰傟側偄 → 0.00，君は一生私を忘れない → 1.00。
    """
    if not s:
        return 0.0
    good = bad = 0.0
    for ch in s:
        o = ord(ch)
        if 0xE000 <= o <= 0xF8FF or o == 0xFFFD:
            bad += 3.0          # 私用区 / 替换符：几乎必然是误解码
        elif o < 0x20 and ch not in "\t\n\r":
            bad += 3.0          # 控制符
        elif 0x80 <= o <= 0x9F:
            bad += 3.0          # C1 控制符
        elif 0x4E00 <= o <= 0x9FFF:
            # 「常用汉字」按 GB2312 **或** Shift_JIS 收录来判。
            # 只看 GB2312 会误伤日文新字体：実 / 嘘 / 雫 这些是日文常用字，
            # 但 GB2312 里没有，会被当成乱码特征——实测「真実はどこに」
            # 因此只拿 0.83 分、被门槛挡在门外。
            # 而真乱码的产物（孨偼堦惗巹傪朰傟側偄）两个表里都查不到。
            if _encodable(ch, "gb2312") or _encodable(ch, "shift_jis"):
                good += 1.0
            else:
                bad += 1.0      # 生僻字：乱码特征
        elif 0x3040 <= o <= 0x30FF:
            good += 1.0         # 平/片假名
        elif 0x3000 <= o <= 0x303F or 0xFF01 <= o <= 0xFF60:
            good += 0.8         # CJK / 全角标点，正常文字的一部分
        elif 0xFF61 <= o <= 0xFF9F:
            bad += 0.5          # 半角片假名：多为误读产物
        elif o < 0x7F:
            good += 0.6         # ASCII
        elif 0x400 <= o <= 0x4FF:
            bad += 1.0          # 西里尔
        elif 0x370 <= o <= 0x3FF:
            bad += 1.0          # 希腊
        elif 0xAC00 <= o <= 0xD7A3:
            good += 0.8         # 谚文：真韩文也长这样，只轻加分
        elif 0xC0 <= o <= 0x24F:
            bad += 0.4          # 拉丁扩展
        else:
            bad += 0.6          # 其它文字系统
    return good / max(good + bad, 1e-9)


def _han_ratio(s):
    """「CJK 汉字占比」：跨编码假设的准入门槛。

    ★ 为什么必须有这个门槛：GB18030 是**全 Unicode 覆盖**的，任何文本都能被它
      编回字节，再按 Big5 解出一堆 GB2312 汉字。于是「可读度提升」这个判据对
      一切非中日的文本都成立——实测俄文 Русский текст 被"翻译"成 妓批扼扼抗我抄，
      韩文、假名为主的文本也都会被乱转。这是纯粹的假阳性，比不修更糟。

    但「中日韩编码互相误读」这个假设本身就有前提：**原文得是中日韩文字**。
    一个满是西里尔字母的字符串不可能是 GBK 文本被当 Shift_JIS 读的产物。

    所以只认「以 CJK 汉字为主」的原文。假名/谚文为主的不算：那种原文更可能
    本来就是正常日文/韩文，而不是乱码。
    """
    if not s:
        return 0.0
    han = sum(1 for ch in s if 0x4E00 <= ord(ch) <= 0x9FFF or 0x3400 <= ord(ch) <= 0x4DBF)
    return han / len(s)


def _common_ratio(s):
    """原文里「一看就是正常文字」的字符占比——跨编码判据的基准线。

    ★ 为什么不用 _plain 当基准：_plain 为了认日文新字体（実/嘘）把判定放宽到
      Shift_JIS，而 GBK 的罕用字（僂/僣/僉）恰好也在 JIS 里，于是乱码原文也能
      拿到 0.75 分。拿它当基准，「真乱码 → 正常文字」的提升就被吃掉大半，
      实测 僂僜僣僉 → ウソツキ 因此被门槛挡掉。

      基准只认真正高频的东西：GB2312 常用汉字、日文假名、ASCII、CJK 标点。
      乱码的产物（孨偼堦惗 / 僂僜僣僉）这些一个都不是，所以基准是 0。
    """
    if not s:
        return 0.0
    n = 0
    for ch in s:
        o = ord(ch)
        if 0x4E00 <= o <= 0x9FFF:
            if _encodable(ch, "gb2312"):
                n += 1
        elif 0x3040 <= o <= 0x30FF:
            n += 1
        elif o < 0x7F or 0x3000 <= o <= 0x303F:
            n += 1
    return n / len(s)


def mojibake_cross(s, min_plain=0.85, min_gain=0.4, min_han=0.5, min_len=3):
    """第二级还原：假设「原始字节被**非 UTF-8** 的编码解成了这堆字」。

    第一级（mojibake_rank）只试 UTF-8 目标，能覆盖「UTF-8 被当 GBK 读」这个
    最常见的情况。但中日韩编码之间互相误读是另一类，UTF-8 完全解不出来——
    它的字节流在 UTF-8 眼里就是非法序列，只能碎成一堆 U+FFFD。

    所以这里把「源编码 × 目标编码」全组合都试一遍，用两个门槛筛：

      1. 严格 decode 必须成功（0 损失）——有丢字符说明字节流本身就不对；
      2. 结果要**明显比原文像正常文字**（min_gain），且本身够干净（min_plain）。

    第 2 条是防假阳性的关键。实测两个真实案例：
      · 孨偼堦惗巹傪朰傟側偄 → plain 0.00，跨编码得 1.00，提升 1.00 → 采信
      · 锟斤拷            → plain 1.00（真的是常用汉字），跨编码得韩文 1.00，
                            提升 0 → 拒绝。这正是「数据已经坏了」该有的表现，
                            此时任何跨编码结果都是编出来的，不能给。

    返回 [(plain 分数, 源编码, 目标编码, 结果), ...]，已排序；空列表 = 没找到。
    """
    # 原文不以 CJK 汉字为主 → 「中日韩互读」这个假设不成立，直接不试。
    # 详见 _han_ratio 的说明：不设这道门槛，任何外文都会被硬转成汉字胡话。
    if _han_ratio(s) < min_han or len(s) < min_len:
        return []
    base = _common_ratio(s)
    rows = []
    for enc in MOJIBAKE_ENCODINGS:
        try:
            raw = _encode_back(s, enc)
        except (UnicodeEncodeError, LookupError):
            continue
        for tgt in MOJIBAKE_TARGETS:
            if _same_encoding_family(enc, tgt):
                continue
            try:
                out = raw.decode(tgt)
            except (UnicodeDecodeError, LookupError):
                continue
            if out == s:
                continue
            p = _plain(out)
            if p < min_plain or (p - base) < min_gain:
                continue
            rows.append((p, enc, tgt, out))
    # 同分时按目标编码名字典序，保证结果稳定可复现（cp932 稳定排在 shift_jis 前）
    rows.sort(key=lambda r: (-r[0], r[2]))
    return rows


def mojibake_explicit(s, src, tgt):
    """显式指定「源编码→目标编码」的还原，不做任何猜测。

    自动路径摸不清时用它。典型：GBK 编的日文被当作 GBK 显示 = 这堆字，
    正确读法是 `--from gbk --to shift_jis`。
    """
    try:
        raw = _encode_back(s, src)
    except (UnicodeEncodeError, LookupError) as e:
        raise ValueError("按 %s 编回字节失败：%s（原文里有该编码表示不了的字符）" % (src, e))
    try:
        return raw.decode(tgt)
    except (UnicodeDecodeError, LookupError) as e:
        raise ValueError("%d 字节按 %s 解不开：%s" % (len(raw), tgt, e))


@dec_name("mojibake", "garbled", "乱码")
def _d_mojibake(s):
    """被误读文本的还原（如「浜哄彧」→「人只」）。

    两级假设：

    · 一级（mojibake_rank）：把字按各候选编码编回字节、再按 **UTF-8** 解。
      覆盖「UTF-8 被当 GBK / Big5 / Latin-1 读」，是最常见的一类。
      损失率 ≤2% 才采信 —— 无损才说明猜对了。

    · 二级（mojibake_cross）：一级损失过大时，说明目标根本不是 UTF-8。
      转而枚举「中日韩编码互相误读」的组合，判据换成「可读度有没有明显提升」。
      典型：孨偼堦惗巹傪朰傟側偄 → 君は一生私を忘れない（GBK 字节按 Shift_JIS 解）。

    两级都不成，才报「数据可能残缺」。
    """
    if all(ord(c) < 128 for c in s):
        raise ValueError("纯 ASCII，不可能是被误读的结果")
    # 一两个字不够下结论：单字 茻 会被无损「解」成 踈（字节碰巧合法），
    # 这种结果比报错更容易误导。乱码是被系统性误读的产物，必然成串出现——
    # 实测最短的真实乱码是 浣犲ソ（3 字符，→ 你好）。
    if len(s) < 3:
        raise ValueError(
            "只有 %d 个字符，不足以判断是不是乱码（乱码通常成串出现）。\n"
            "若确定是，用 --from/--to 显式指定当初的编码对。" % len(s))
    rows = mojibake_rank(s)
    rejected = None
    if rows:
        ratio, bad, enc, out = rows[0]
        # 无损还不够，还得**解完不能显著更差**。字节流碰巧是合法 UTF-8 的情况
        # 不少：あいうえお → ƦƨƪƬƮ、茻 → Ɵ，都是 0 损失却是纯垃圾。
        # 但门槛只能设成「不许变差」而不是「必须变好」——浣犲ソ → 你好 里原文
        # 含一个假名 ソ，plain 就已经是 1.0 了，要求严格提升会把正确解判掉。
        # 第一级的本职是看损失率，plain 只负责拦明显的垃圾。
        if ratio <= 0.02 and _plain(out) >= _plain(s) - 0.05:
            return out
        if ratio <= 0.02:
            rejected = (enc, out)    # 无损但解得更差 → 巧合，不是真乱码
    else:
        ratio, bad, enc, out = 1.0, len(s), "?", s
    # ---- 二级：换成非 UTF-8 的目标编码再试
    cross = mojibake_cross(s)
    if cross:
        p, cenc, ctgt, cout = cross[0]
        others = ["%s→%s" % (r[1], r[2]) for r in cross[1:]]
        # stdout 有缓冲、stderr 没有，不 flush 会跑到结果后面去
        sys.stdout.flush()
        sys.stderr.write(
            "\n  [跨编码] 按 %s 编回字节、按 %s 解"
            "（可读度 %.0f%% → %.0f%%）%s\n"
            % (cenc, ctgt, _common_ratio(s) * 100, p * 100,
               "；另有等价解 " + "、".join(others[:3]) if others else ""))
        sys.stderr.flush()
        return cout
    if rejected is not None:
        renc, rout = rejected
        raise ValueError(
            "按 %s 能无损解出 %r，但结果并不比原文更像正常文字。\n"
            "这只是字节碰巧合法，不是真的被误读过——别把它当答案。\n"
            "若你确信原文是乱码，用 --from/--to 显式指定当初的编码对。"
            % (renc, rout))
    # 只有几乎无损才认。损失率 >2% 说明原始字节流本身就缺字节，
    # 这时候硬输出等于把猜测当成答案，比报错更坑。
    # 但也不能只报错什么都不给——把最佳猜测和损失率一起亮出来，
    # 让使用者自己判断哪一段还能信。
    if ratio > 0.02:
        # 结果本身可能是多行，直接接在冒号后面会把缩进冲掉、还跟报错文字
        # 挤在一起。统一另起一行，逐行缩进四格。
        guess = out.replace("\ufffd", "?")
        body = "\n".join("    " + ln for ln in (guess.splitlines() or [""]))
        raise ValueError(
            "还原损失 %.1f%%（%d 个替换字符，假设 %s）。\n"
            "既不是 UTF-8 被误读，也不像中日韩编码互相误读——原始字节流可能真的有缺失。\n"
            "\n"
            "  最佳猜测（? = 缺失处，不可全信）：\n"
            "%s\n"
            "\n"
            "  若你已知当初的编码对，直接指定：dec mojibake --from gbk --to shift_jis '...'"
            % (ratio * 100, bad, enc, body))
    return out


def mojibake_best(s):
    """宽松还原：不管损失多大都返回最佳假设。

    用于「作者给的数据本身就是残缺的」这类谜题——这时候不存在"更原始的来源"，
    能做的只有把最可能的还原摊开、把缺失位置标成 ?，让人自己靠上下文补。
    返回 (结果, 损失率, 替换字符数, 编码名)。

    跨编码能无损解出时优先用它，此时损失率记 0、编码名写成 `源→目标`。
    """
    rows = mojibake_rank(s)
    if rows:
        ratio, bad, enc, out = rows[0]
        if ratio <= 0.02:
            return out, ratio, bad, enc
    else:
        ratio, bad, enc, out = 1.0, len(s), "?", s
    cross = mojibake_cross(s)
    if cross:
        p, cenc, ctgt, cout = cross[0]
        return cout, 0.0, 0, "%s→%s" % (cenc, ctgt)
    return out, ratio, bad, enc


def readability(s):
    """「正常文字占比」0~1：汉字看是否 GB2312 常用，假名算正常。

    用它判断"解够了没有"比看损失率可靠。UTF-8 被 GBK 误读后会产出
    鑷 / 嵆 / 鍖 / 遠 这类 GB2312 之外的生僻字，正常中文则几乎全在里面。
    实测：正常中文 100%、一层乱码 26%、两层乱码 89%。

    ★ 分子分母都只看中日韩文字，ASCII 不计入。
    否则解过头变成 `?1?7?1?7` 那种 ASCII 噪音时，反而会被算成高可读率，
    导致 --deep 一路解到烂。没有这类字符时直接返回 0。

    ★ 假名也算「好」，半角片假名不算。早先只统计 CJK 汉字，结果纯假名的正确
      解（おはよう、ニセモノ）可读率恒为 0%，--deep 会一路跑满还在原文打转。
    """
    units = []
    for ch in s:
        o = ord(ch)
        if 0x4E00 <= o <= 0x9FFF:
            units.append(_encodable(ch, "gb2312"))
        elif 0x3040 <= o <= 0x30FF:
            units.append(True)      # 平/片假名：正常文字
        elif 0xFF61 <= o <= 0xFF9F:
            units.append(False)     # 半角片假名：多为误读产物
    if not units:
        return 0.0
    return sum(1 for u in units if u) / len(units)


def mojibake_deep(s, threshold=50, max_rounds=5):
    """反复还原，直到「正常文字占比」达到 threshold（0~100）为止。

    threshold 由使用者指定：想解干净就调高（如 80），只要大致能读就调低。
    默认 50 对应"一半以上已经是常见汉字"。

    返回 (最佳结果, 每层记录, 停在第几层)。
    每层记录格式 [(编码名, 损失率, 该层可读率), ...]。

    ★ 可读率不是单调上升的。实测一串双层乱码的逐层可读率是
      36.6% → 31.1% → 52.5% → 48.6%，中间会先降后升再降。
      所以不能"一提升就继续"，而是每层都记下来、最后取可读率最高的那层，
      解过头了也能自动退回去。

    注意：只对"整段层数一致"的乱码有效。如果同一行里有的部分已经解开、
    有的还没有（混合层数），无脑递归会把已经解好的部分重新弄坏——那种
    情况必须人工切段。所以这里 max_rounds 默认 5 层封顶。
    """
    lo = max(0, min(100, int(threshold)))
    cur = s
    layers = []
    # (可读率, 内容, 层号)
    best = (readability(cur), cur, 0)
    for n in range(1, max_rounds + 1):
        # 每层开头先看当前是否已经够用——阈值 0 时应当直接原样返回
        if readability(cur) * 100 >= lo:
            break
        rows = mojibake_rank(cur)
        # 一层 UTF-8 假设不成立时，这一层可能就是「中日韩编码互相误读」——
        # 不试的话 --deep 只会在原地打转，跑满 5 层仍然交回原文。
        cross = [] if (rows and rows[0][0] <= 0.02) else mojibake_cross(cur)
        if rows and rows[0][0] <= 0.02:
            ratio, bad, enc, out = rows[0]
        elif cross:
            _, cenc, ctgt, out = cross[0]
            ratio, enc = 0.0, "%s→%s" % (cenc, ctgt)
        elif rows:
            ratio, bad, enc, out = rows[0]
        else:
            break
        if out == cur:
            break
        cur = out
        rd = readability(cur)
        layers.append((enc, ratio, rd))
        if rd > best[0]:
            best = (rd, cur, n)
        if rd * 100 >= lo:
            break
    return best[1], layers, best[2]


# ---------------------------------------------------------------- 评分 / 识别

COMMON_EN = set("the be to of and in that have it for not on with he as you do at "
                "this but his by from they we say her she or an will my one all "
                "would there their what so up out if about who get which go me".split())

# 高频汉字。用来区分"真中文"和"UTF-16 误读出来的假中文"（后者全是生僻字）
COMMON_CN = set("的一是了我不人在他有这个上们来到时大地为子中你说生国年着就那和要"
                "她出也得里后自以会家可下而过天去能对小多然于心学么之都好看起发当没"
                "成只如事把还用第样道想作种开美总从无情己面最女但现前些所同日手又行"
                "意动方期它头经长儿回位分爱老因很给名法间斯知世什两次使身者被高已亲"
                "其进此话常与活正感")
CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def score(text):
    """越大越像人能读的明文。负数表示基本可以丢掉。"""
    if not text:
        return -100.0
    s = text
    n = len(s)
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t ")
    ctrl = sum(1 for c in s if ord(c) < 32 and c not in "\n\t ")
    cjk = sum(1 for c in s if "\u4e00" <= c <= "\u9fff")
    # 假名（平假名 + 片假名）也是正常文字，必须单独计分。
    # 否则日文结果一分不得，反而输给解出一堆 `?` 的国际摩斯——和文モールス
    # 就走这条路：同一串符号用 morse 解得 `? I + ? U ?`，用 wabun 才是假名，
    # 但因为假名不加分，auto 会选前者。
    kana = sum(1 for c in s if "\u3040" <= c <= "\u30ff")
    cn_hit = sum(1 for c in s if c in COMMON_CN)
    ascii_letters = sum(1 for c in s if c.isascii() and c.isalpha())
    digits = sum(1 for c in s if c.isdigit())
    spaces = sum(1 for c in s if c == " ")

    sc = 0.0
    sc += 100.0 * printable / n
    sc -= 60.0 * ctrl / n
    # 替换符（U+FFFD）说明字节流不是合法文本，重罚，否则乱码会靠"可打印"虚高胜出
    sc -= 300.0 * s.count("\ufffd") / n

    # 中文：真中文（含高频字）才给满分，乱码中文打折
    if cjk:
        ratio = cn_hit / cjk
        sc += 40.0 * (cjk / n) * (0.3 + 0.7 * ratio)

    if kana:
        # 假名没有"常用字表"可比，给一个低于汉字、但足以压过乱码的固定权重
        sc += 35.0 * (kana / n)

    sc += 25.0 * ascii_letters / n
    sc += 10.0 * digits / n
    sc += 15.0 * spaces / n

    # 常见英文词加成
    words = re.findall(r"[A-Za-z]{2,}", s.lower())
    if words:
        hits = sum(1 for w in words if w in COMMON_EN)
        sc += 60.0 * hits / len(words)

    # 全是同一字符 / 全大写乱码，扣分
    if len(set(s)) <= 2 and n > 4:
        sc -= 30
    # 长串无可读词，扣分
    if n > 20 and not words and cjk == 0:
        sc -= 25

    # 熵过低也扣（像重复填充）
    try:
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        ent = -sum((v / n) * math.log2(v / n) for v in freq.values())
        if ent < 1.5:
            sc -= 15
    except Exception:
        pass
    return sc


# 自动识别：先看"结构特征"，命中就高优先；没有特征才退回宽松候选。
# 关键设计：rot13/rot47/atbash 不在 auto 里——它们对任何文本都能"成功"且输出同样可读，
# 放进来会永远污染结果。它们只在 brute 里作为候选列出，由人判断。
STRUCT_BONUS = 60.0

LOOSE_ORDER = [
    "base64", "base64url", "base32", "base58", "base85", "ascii85",
    "base91", "base62", "qp", "gzip", "dec", "oct", "mojibake",
]


def acceptable(out, thr=0.15):
    """解码结果必须基本可打印，否则是乱码，直接丢"""
    if not out:
        return False
    n = len(out)
    # U+FFFD 替换符的 isprintable() 是 True，光看可打印率会把乱码放行 —— 它是解码失败的铁证
    bad = sum(1 for c in out if not (c.isprintable() or c in "\n\r\t") or c == "\ufffd")
    return bad / n <= thr


def structural_candidates(text):
    """按格式特征判断"这像什么编码"。顺序即优先级。"""
    t = text.strip()
    compact = re.sub(r"\s+", "", t)
    cands = []

    # Punycode：`xn--` 前缀是强签名，看到就该直接认。必须排在最前 —— 这类串
    # 长度常是 4 的倍数、字符集又落在 base64url 里（- 合法），否则会被抢走。
    if re.search(r"(?im)^[ \t]*xn--", t):
        cands.append("punycode")
    if re.search(r"[\u2800-\u28ff]", t):
        cands.append("braille")
    # 摩斯符号的字符集必须把**全角变体**也包进来。
    # 实测踩过：日文谜题里常写成 `・`(U+30FB 片假名中点) 和 `－`(U+FF0D 全角连字符)，
    # 而这里原先只有 `·`(U+00B7) / `—`(U+2014) 那些，于是 auto 直接判成
    # 「不是摩斯」、连候选都不进——`dec wabun` 却因为内部有 replace 能正常解，
    # 表现为「手动指定可以、auto 就不行」，非常难猜。
    if re.fullmatch(r"[.\-\u00b7\u2022\u2014\u2013\u2212\uff0d\uff0e\u30fb\u2027_\s/|]{4,}", t):
        # 国际摩斯与和文モールス在符号层面同形（`....` 国际是 H、和文是 ヌ），
        # 光看符号分不出来，靠「哪些码在表里查不到」判：
        # 只要有一段不在国际表里，就只可能是和文（`--.-.` 国际根本没有）。
        # 反过来全部能按国际解释时优先国际 —— 它的覆盖率更高，而和文几乎
        # 总能"硬解"出一串无意义假名，不能让它靠这个赢。
        norm = (t.replace("·", ".").replace("•", ".").replace("・", ".")
                 .replace("．", ".").replace("‧", ".")
                 .replace("—", "-").replace("－", "-").replace("–", "-")
                 .replace("−", "-").replace("_", "-"))
        segs = [x for x in re.split(r"[/\s]+", norm.strip()) if x]
        if segs and any(x not in MORSE for x in segs):
            cands.append("wabun")
        else:
            cands.append("morse")
    if re.fullmatch(r"[01\s]{16,}", t):
        # 纯 0/1 位流没有任何歧义，直接定死；否则 0/1 恰好是 base64 字符集子集，会被 base64 抢走
        return ["bin"]
    if re.search(r"%[0-9A-Fa-f]{2}", t):
        cands.append("url")
    if re.search(r"&(#\d{1,7}|#x[0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});", t):
        cands.append("html")
    # \u4F60 / \u{1F600} / \xNN / U+4F60 / %u4F60 —— 全归 unicode 一族
    if re.search(r"\\u\{?[0-9a-fA-F]{4,6}\}?|\\x[0-9a-fA-F]{2}|U\+[0-9a-fA-F]{4,6}|%u[0-9a-fA-F]{4}", t):
        cands.append("unicode")

    # 进制/Base 系列靠"字符集 + 长度"约束，避免纯英文单词被误判
    body = compact.rstrip("=")
    if re.fullmatch(r"[A-Z2-7]+=*", compact) and len(compact) >= 8 and len(compact) % 8 == 0:
        cands.append("base32")
    # UTF-32 hex：8 位一组、多数码点带前导零（00000023 00007ED9 ...）。
    # ★ 必须排在 base16 之前 —— 它同样合法 hex，但只有按 UTF-32 解才可读。
    if len(compact) >= 16 and len(compact) % 8 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        groups = [compact[i:i + 8] for i in range(0, len(compact), 8)]
        lead0 = sum(1 for g in groups if g[:4] == "0000" or g[4:] == "0000")
        if lead0 * 2 >= len(groups):
            cands.append("utf32be")
    hexbody = re.sub(r"^(0x)?", "", compact)
    if re.fullmatch(r"[0-9a-fA-F]+", hexbody) and len(hexbody) >= 4 and len(hexbody) % 2 == 0:
        cands.append("base16")
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) and len(compact) % 4 == 0 and len(compact) >= 8:
        cands.append("base64")
    if re.fullmatch(r"[A-Za-z0-9_\-]+={0,2}", compact) and len(compact) % 4 == 0 and len(compact) >= 8:
        cands.append("base64url")
    # base58 字符集排除了 0OIl，特征比较强
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{6,}", compact) and not re.fullmatch(r"[0-9a-fA-F]+", compact):
        cands.append("base58")
    return cands


def try_decode(text, name):
    fn = DECODERS.get(name)
    if not fn:
        return None
    try:
        out = fn(text)
    except Exception:
        return None
    if not out or out == text:
        return None
    return out


def brute(text, top=15):
    """所有编码都试，按可读性排序（这里才包含 rot13/rot47/atbash 这类模糊变换）"""
    names = list(DECODERS) + ["rot13", "rot47", "atbash"]
    results = []
    for name in names:
        if name == "braillebits":
            continue
        fn = DECODERS.get(name)
        if not fn:
            continue
        try:
            out = fn(text)
        except Exception:
            continue
        if not out or out == text:
            continue
        if not isinstance(out, str):
            out = as_text(out)
        if not acceptable(out, 0.25):
            continue
        results.append((score(out), name, out))
    results.sort(key=lambda x: -x[0])
    seen = set()
    uniq = []
    for sc, name, out in results:
        k = out[:80]
        if k in seen:
            continue
        seen.add(k)
        uniq.append((sc, name, out))
    return uniq[:top]


# ---------------------------------------------------------------- 矩阵重排
# 常见手法：文本切成定长块 → 排成矩阵 → 换一种读法。
# 典型链路：base64 → 每 2 字符是 base36 的一个字节 → 3x3 转置 → "nevermore"
# 判据：块数是完全平方数（4/9/16/25）时，转置几乎是必试项。

def _blocks(text, w):
    return [text[i:i + w] for i in range(0, len(text), w)]


def _read(m, mode):
    r, c = len(m), len(m[0])
    if mode == "行优先":
        return "".join("".join(row) for row in m)
    if mode == "列优先":
        return "".join(m[i][j] for j in range(c) for i in range(r))
    if mode == "行优先-反行序":
        return "".join("".join(row) for row in m[::-1])
    if mode == "列优先-反列序":
        return "".join(m[i][j] for j in range(c - 1, -1, -1) for i in range(r))
    if mode == "蛇形行":
        return "".join("".join(row) if k % 2 == 0 else "".join(row[::-1]) for k, row in enumerate(m))
    if mode == "蛇形列":
        return "".join("".join(m[i][j] for i in range(r)) if j % 2 == 0
                       else "".join(m[i][j] for i in range(r - 1, -1, -1))
                       for j in range(c))
    if mode == "每行反转":
        return "".join("".join(row[::-1]) for row in m)
    if mode == "反转整体":
        return "".join("".join(row) for row in m)[::-1]
    return ""


def grid_variants(text, rows=None, cols=None, block_width=1):
    """按 block_width 切块后排成矩阵，输出各种读法。

    默认块宽 2：因为很多谜题把一个字节写成两位某进制数字（如 base36 的 "2T"=101）。
    """
    blocks = _blocks(text, block_width)
    n = len(blocks)
    out = []
    dims = []
    if rows and cols:
        dims = [(rows, cols)]
    else:
        import math
        r0 = int(math.isqrt(n))
        if r0 * r0 == n:
            dims.append((r0, r0))
        for r in range(2, min(n, 12) + 1):
            if n % r == 0 and n // r <= 40:
                dims.append((r, n // r))
    seen = set()
    for r, c in dims:
        if r * c != n:
            continue
        m = [blocks[i * c:(i + 1) * c] for i in range(r)]
        for mode in ("行优先", "列优先", "行优先-反行序", "列优先-反列序",
                     "蛇形行", "蛇形列", "每行反转", "反转整体"):
            v = _read(m, mode)
            if v in seen:
                continue
            seen.add(v)
            out.append(("%dx%d %s" % (r, c, mode), v))
    return out


def blocks_to_bytes(text, width=2, radix=36, alphabet=None):
    """把定长块按 radix 转成字节。典型：width=2, radix=36 -> 两位 base36 = 一个字节。"""
    alpha = alphabet or "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:radix]
    text = text.strip()
    out = bytearray()
    for i in range(0, len(text) - width + 1, width):
        chunk = text[i:i + width]
        try:
            v = 0
            for ch in chunk:
                v = v * radix + alpha.index(ch.upper() if alpha.isupper() else ch)
        except ValueError:
            return None
        if v > 255:
            return None
        out.append(v)
    return bytes(out)


def auto(text, depth=3, _memo=None):
    """递归剥皮：每一步在所有编码里挑"得分 + 结构奖励"最高的分支"""
    if _memo is None:
        _memo = {}
    # key 直接用完整文本：hash() 有碰撞风险，而且早期版本只取 text[:200]，
    # 导致前 200 字符相同的两个长文本会共享缓存、拿到对方的结果。
    key = (text, depth)
    if key in _memo:
        return _memo[key]

    best = (score(text), text, [])
    if depth <= 0:
        _memo[key] = best
        return best

    struct = structural_candidates(text)
    proven = [(n, STRUCT_BONUS) for n in struct]
    if not proven:
        proven = [(n, -0.5 * i) for i, n in enumerate(LOOSE_ORDER)]

    seen = set()
    for name, bonus in proven:
        if name in seen:
            continue
        seen.add(name)
        out = try_decode(text, name)
        if out is None or not acceptable(out) or len(out) > 200000:
            continue
        # 解码后长度骤减 = 信息被丢掉了，不算有效解码。
        # 实例：四行 punycode 解出的日文再被 base91「解」成单个 "G"，
        # 而 score() 算的全是比例，一字符输出各项都是 100%，得分反而
        # 高过正确的日文，导致 auto 选错路径。阈值取 10%：中文 base64
        # 的压缩比约 25%（4 字符→1 汉字），不会被误伤。
        if len(text) >= 8 and len(out) < max(2, len(text) * 0.1):
            continue
        sub_sc, final, path = auto(out, depth - 1, _memo)
        cand = sub_sc + bonus
        if cand > best[0] + 1e-9:
            best = (cand, final, [name] + path)
    _memo[key] = best
    return best


# ---------------------------------------------------------------- CLI

def read_input(args, want_bytes=False):
    """把参数列表解析成待处理内容。

    约定：传进来的 args **已经**去掉子命令和编码名，剩下的就是文本部分。
    早期版本在这里擅自 rest[1:] 砍掉第一项，于是每个调用方都得"多传一个
    用来被吃掉"的参数，靠巧合才对——现在改成显式约定。
    """
    if "-f" in args or "--file" in args:
        idx = args.index("-f") if "-f" in args else args.index("--file")
        if idx + 1 >= len(args):
            raise SystemExit("错误：-f/--file 后面要跟文件路径")
        path = os.path.expanduser(args[idx + 1])
        # 直接 open 失败会抛 FileNotFoundError，一路冒泡到顶层变成整屏
        # Python traceback——用户看到的是一堆内部栈，而不是"文件没找到"。
        # 这里统一转成人话。另外 expanduser 是必须的：加了引号的
        # "~/Documents/x.txt" 不会被 shell 展开，open() 也不认 ~。
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except FileNotFoundError:
            raise SystemExit("错误：文件不存在：%s" % path)
        except IsADirectoryError:
            raise SystemExit("错误：%s 是个目录，要指向具体文件" % path)
        except PermissionError:
            raise SystemExit("错误：没有读取权限：%s" % path)
        except OSError as e:
            raise SystemExit("错误：读取 %s 失败：%s" % (path, e))
        args = args[:idx] + args[idx + 2:]
        # want_bytes 用于 enc hex / enc base64 这类"把原始字节转成文本表示"的场景。
        # 不加这个开关，二进制文件会先被 as_text 用 U+FFFD 替换掉，
        # 输出的 hex 根本不是文件的真实字节。
        if want_bytes:
            return data, args
        # 文件可能是 UTF-8 文本，也可能是二进制（压缩流 / UTF-16 / 图片）。
        # 以前无条件 as_text（UTF-8 + replace），二进制会被替换成 U+FFFD，
        # BOM 和 gzip 魔数全毁，`dec utf16 -f x.txt` 直接解不出来。
        # 这里先按 UTF-8 严格解，失败就认定是二进制、用 latin-1 逐字节承载，
        # 这样 raw_bytes() 能原样还原回去。
        try:
            return data.decode("utf-8"), args
        except UnicodeDecodeError:
            return data.decode("latin-1"), args
    # 不能按「以 - 开头」过滤：摩斯电码本身就长这样（`--.-.`、`-....`），
    # 一过滤整段输入就没了，表现为莫名其妙的「空输入」。已知选项
    # （-q / --best / --deep / --depth）在 main() 里都已消费，这里直接拼接。
    return " ".join(args), args


def main():
    argv = sys.argv[1:]
    quiet = "-q" in argv or "--quiet" in argv
    best = "--best" in argv
    argv = [a for a in argv if a not in ("-q", "--quiet", "--best")]
    # --deep [N]：反复还原直到「正常文字占比」达到 N%（0~100，默认为 50）。
    # N 可选，写成 --deep 80 或直接 --deep（等价 50）。
    deep = None
    if "--deep" in argv:
        i = argv.index("--deep")
        if i + 1 < len(argv) and re.fullmatch(r"\d+", argv[i + 1]):
            deep = max(0, min(100, int(argv[i + 1])))
            argv = argv[:i] + argv[i + 2:]
        else:
            deep = 50
            argv = argv[:i] + argv[i + 1:]
    depth = 3
    for flag in ("--depth", "-d"):
        if flag in argv:
            i = argv.index(flag)
            depth = int(argv[i + 1])
            argv = argv[:i] + argv[i + 2:]

    # --from <源编码> / --to <目标编码>：显式指定乱码的编码对，完全不猜。
    # 自动路径摸不清时（或已知作者用的编码）用它，结果可复现。
    mb_from = mb_to = None
    for flag, key in (("--from", "f"), ("--to", "t")):
        while flag in argv:
            i = argv.index(flag)
            if i + 1 >= len(argv):
                print("%s 后面要跟一个编码名（如 gbk / shift_jis）" % flag)
                return 2
            if key == "f":
                mb_from = argv[i + 1]
            else:
                mb_to = argv[i + 1]
            argv = argv[:i] + argv[i + 2:]

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0

    cmd = argv[0]

    if cmd == "list":
        for name in sorted(DECODERS):
            mark = "enc" if name in ENCODERS else "   "
            print("  %-20s %s" % (name, mark))
        return 0

    if cmd == "auto":
        text, _ = read_input(argv[1:])
        sc, final, path = auto(text, depth)
        if quiet:
            print(final)
            return 0
        print("原始：%s" % (text[:120] + ("…" if len(text) > 120 else "")))
        if path:
            print("路径：%s" % " → ".join(path))
            print("得分：%.1f" % sc)
        else:
            print("没有可靠的编码路径（原样输出）")
            # 只说「没有可靠路径」等于什么都没说：用户分不清是「这压根不是编码」
            # 还是「是乱码但数据坏了」。这里再探一次 mojibake，把损失率亮出来。
            try:
                mb_out, mb_ratio, mb_bad, mb_enc = mojibake_best(text)
            except Exception:
                mb_ratio = 0.0
            if 0 < mb_ratio <= 0.6:
                # stdout 带缓冲、stderr 不带，不 flush 的话提示会窜到上面去
                sys.stdout.flush()
                sys.stderr.write(
                    "\n  [提示] 最接近的是 mojibake（假设 %s，损失 %.1f%%，%d 处缺失）：\n"
                    "    %s\n"
                    "  数据本身可能有损坏。看残缺全貌用 `dec mojibake --best`，"
                    "或回头找更原始的来源。\n"
                    % (mb_enc, mb_ratio * 100, mb_bad,
                       mb_out.replace("\ufffd", "?")[:120]))
        print("结果：")
        print(final)
        return 0

    if cmd == "blocks":
        args2 = list(argv)
        width = int(os.environ.get("ARG_BLOCK_WIDTH", "2"))
        radix = int(os.environ.get("ARG_BLOCK_RADIX", "36"))
        for flags, key in ((( "-w", "--width"), "w"), (("-r", "--radix"), "r")):
            for flag in flags:
                if flag in args2:
                    i = args2.index(flag)
                    val = int(args2[i + 1])
                    args2 = args2[:i] + args2[i + 2:]
                    if key == "w":
                        width = val
                    else:
                        radix = val
                    break
        text, _ = read_input(args2[1:])
        b = blocks_to_bytes(text, width, radix)
        if b is None:
            print("无法按 width=%d radix=%d 解析（字符超出该进制范围，或有块值 >255）" % (width, radix))
            return 1
        print("bytes: %s" % list(b))
        print("ascii: %s" % b.decode("latin-1"))
        try:
            print("utf-8: %s" % b.decode("utf-8"))
        except Exception:
            pass
        return 0

    if cmd == "grid":
        args2 = list(argv)
        rows = None
        cols = None
        bw = int(os.environ.get("ARG_GRID_WIDTH", "1"))
        for flags, key in ((("--rows", "-R"), "r"), (("--cols", "-C"), "c"), (("--width", "-W"), "w")):
            for flag in flags:
                if flag in args2:
                    i = args2.index(flag)
                    val = int(args2[i + 1])
                    args2 = args2[:i] + args2[i + 2:]
                    if key == "r":
                        rows = val
                    elif key == "c":
                        cols = val
                    else:
                        bw = val
                    break
        text, _ = read_input(args2[1:])
        for t in grid_variants(text, rows, cols, bw):
            print("  %-22s %s" % (t[0], t[1]))
        return 0

    if cmd == "brute":
        text, _ = read_input(argv[1:])
        rows = brute(text)
        if quiet:
            for _, _, out in rows:
                print(out)
            return 0
        print("对 %r 尝试所有编码：\n" % (text[:60] + ("…" if len(text) > 60 else "")))
        for sc, name, out in rows:
            out1 = out.replace("\n", "\\n")
            print("  %-14s %6.1f  %s" % (name, sc, out1[:110] + ("…" if len(out1) > 110 else "")))
        return 0

    if cmd in ("dec", "decode", "enc", "encode"):
        if len(argv) < 2:
            print("用法：codec.py %s <编码名> <文本>" % cmd)
            return 2
        name = argv[1]
        # enc + -f：直接用文件原始字节编码（enc hex / enc base64 的真实需求）。
        # dec 仍走文本模式——二进制流解码请用 stego.py，codec 面向文本。
        want_bytes = cmd.startswith("enc") and ("-f" in argv or "--file" in argv)
        text, _ = read_input(argv[2:], want_bytes=want_bytes)
        if not text:
            text = ""
        table = DECODERS if cmd.startswith("dec") else ENCODERS
        # dec mojibake --from X --to Y：显式编码对，不猜。
        # 只给一侧时另一侧取默认（源 gb18030 / 目标 utf-8），并在 stderr 说清。
        if cmd.startswith("dec") and name == "mojibake" and (mb_from or mb_to):
            src = mb_from or "gb18030"
            tgt = mb_to or "utf-8"
            try:
                out = mojibake_explicit(text, src, tgt)
            except ValueError as e:
                print("失败：%s" % e)
                return 1
            sys.stdout.flush()
            sys.stderr.write(
                "\n  [显式] 按 %s 编回字节 → 按 %s 解%s\n"
                % (src, tgt,
                   "（未指定的那一侧用了默认值）" if not (mb_from and mb_to) else ""))
            sys.stderr.flush()
            print(out)
            return 0
        # dec mojibake --best：谜题里数据本身残缺时，强制给出最佳猜测，
        # 缺失处标 ?，并把损失率告诉使用者。
        if cmd.startswith("dec") and name == "mojibake" and best:
            out, ratio, bad, enc = mojibake_best(text)
            print(out.replace("\ufffd", "?"))
            # stdout 带缓冲、stderr 不带，不 flush 的话提示会跑到结果前面
            sys.stdout.flush()
            if "\u2192" in enc:
                # 跨编码无损解出：enc 形如 gb18030→shift_jis
                sys.stderr.write(
                    "\n  [跨编码] 按 %s 解，完整无损（不是残缺数据）\n"
                    % enc.replace("\u2192", " 编回字节、按 "))
            elif ratio > 0:
                sys.stderr.write(
                    "\n  [提示] 损失 %.1f%%（%d 处缺失，假设 %s）；? 处需要靠上下文猜\n"
                    % (ratio * 100, bad, enc))
            return 0
        # dec mojibake --deep [N]：反复还原直到「正常文字占比」达到 N%
        if cmd.startswith("dec") and name == "mojibake" and deep is not None:
            out, layers, used = mojibake_deep(text, deep)
            # 先把层级信息打到 stderr，再用一个空行隔开后输出结果。
            # 顺序反过来（结果在前、诊断在后）时，长文本会把它俩推得很远，
            # 末尾那一大段说明反而抢了视线；放前面则结果紧接其后，一眼看到。
            # stderr 不进管道，所以重定向/管道时结果依然是干净的。
            if layers:
                for n, (enc, ratio, rd) in enumerate(layers, 1):
                    sys.stderr.write(
                        "  第 %d 层  %-12s 损失 %5.1f%%  可读率 %3.0f%%%s\n"
                        % (n, enc, ratio * 100, rd * 100,
                           "  ←采信" if n == used else ""))
            sys.stderr.write(
                "  采信第 %d 层（可读率 %.0f%%，阈值 %d%%）%s\n\n"
                % (used, readability(out) * 100, deep,
                   "；残片若仍乱，可能是混合层数，需手工切段" if layers else ""))
            sys.stderr.flush()
            print(out.replace("\ufffd", "?"))
            sys.stdout.flush()
            return 0
        fn = table.get(name)
        if not fn:
            print("不支持的编码：%s（用 codec.py list 看全部）" % name)
            return 2
        try:
            out = fn(text)
        except Exception as e:
            print("失败：%s" % e)
            return 1
        print(out)
        return 0

    print("未知子命令：%s" % cmd)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
