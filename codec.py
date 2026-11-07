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
  convert <text>       字节 = 进制 × 字符编码，两个维度分开指定
                       -r 进制（2/8/10/16/36，默认 16）
                       -e 编码（utf-8/gbk/gb18030/big5/shift_jis/ascii/
                               latin-1/auto，默认 auto）
                       ★ auto 只表示「我替你挑一个能解的」，不代表这批字节
                         只有这一种读法。纯 ASCII 时任何 ASCII 兼容编码结果
                         都相同，报告会写成「ASCII（与编码无关）」；真有歧义
                         （能解出不同的通顺文字）时会把候选一并列出。

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
  --katakana           配合 dec wabun：输出片假名（默认平假名）

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
  codec.py convert '228 189 160' -r 10                 # 十进制字节 → UTF-8 → 你
  codec.py convert 'C0EB' -r 16                        # → 离（auto 认出 GB 系）
  codec.py convert 'C0EB' -r 16 -e big5                # 同一批字节换编码 → 燭
  codec.py convert '2W33342T' -r 36                    # base36 每两位一字节 → hope
"""
import sys
import os
import re
import math
import base64
import binascii
import zlib
import bz2
import gzip
import html
import urllib.parse
import json
import unicodedata

# ---------------------------------------------------------------- 基础设施：注册表 / 装饰器 / str↔bytes

ENCODERS = {}
DECODERS = {}

# `-q` 的静默开关，由 main() 设置。诊断提示一律走 _hint()。
_QUIET = False


def _hint(msg):
    """诊断提示的统一出口（「解释」类信息，`-q` 时静默）。

    和 sys.stderr.write 分工，两者不能混：
      · _hint()      用了哪对编码、损失率、分段还原了几段 —— 可以不要
      · stderr.write 失败原因、数据损坏警告 —— 不能不要，脚本靠它排查

    先 flush stdout 再写 stderr：stdout 带缓冲、stderr 不带，
    不 flush 的话提示会跑到结果后面去。
    """
    if _QUIET:
        return
    sys.stdout.flush()
    sys.stderr.write(msg)
    sys.stderr.flush()


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


def _bin_str(b):
    """把二进制塞进 str：1 字符 = 1 字节（latin-1 视角）。

    codec 的 enc 一律返回 str。压缩流 / UTF-16 / uu 这类结果本质是二进制，
    用 latin-1 承载才能让 `dec` 那边的 raw_bytes() 原样还原，也才能接着
    `enc b64` 串成管道。直接看是乱码——这是设计，不是 bug。
    """
    return b.decode("latin-1")


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


@enc_name("base32hex", "b32hex")
def _e_b32hex(s):
    return base64.b32hexencode(as_bytes(s)).decode()


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


@enc_name("base62", "b62")
def _e_b62(s):
    # 解码端会拿三种字母表轮着试，编码固定用最常见的那种（0-9A-Za-z）
    alpha = B62_SETS[0]
    n = int.from_bytes(as_bytes(s), "big")
    if n == 0:
        return ""
    out = []
    while n:
        n, r = divmod(n, 62)
        out.append(alpha[r])
    return "".join(reversed(out))


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


@enc_name("ascii85", "a85")
def _e_a85(s):
    return base64.a85encode(as_bytes(s)).decode()


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


@enc_name("base91", "b91")
def _e_b91(s):
    """base91 编码：每 13/14 位吐两个字符，是解码那段的反向。"""
    data = as_bytes(s)
    out = []
    b = n = 0
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(B91[v % 91])
            out.append(B91[v // 91])
    if n:
        out.append(B91[b % 91])
        if n > 7 or b > 90:
            out.append(B91[b // 91])
    return "".join(out)


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
    out = as_text(bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)))
    # 末尾的 0x00 是「位数补齐到 8 的倍数」留下的填充，没有信息量。
    # 留着结果是带不可见字符的：终端看不出区别，但复制走、比较、再编码都会出问题。
    return out.rstrip("\x00")


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


def blocks_to_bytes(text, width=2, radix=36, alphabet=None):
    """把定长块按 radix 转成字节。典型：width=2, radix=36 -> 两位 base36 = 一个字节。

    返回 (bytes, 错误说明)。

    ★ 尾部不足一组时**报错，不丢**。原实现用 `range(0, len-width+1, width)`
      静默丢弃末尾几个字符：`2W333`（5 字符）解出 `ho`、`2W3334Z`（7 字符）
      解出 `hop`，都不提示。结果看着正常，数据末尾却被吃掉了——和零宽字符
      那次是同一类错误，静默丢失比报错危险。
    """
    alpha = alphabet or "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:radix]
    text = text.strip()
    if not text:
        return None, "没有输入"
    if width < 1:
        return None, "块宽必须 >= 1（现在是 %d）" % width
    if len(text) % width:
        return None, ("长度 %d 不是块宽 %d 的倍数，末尾 %d 个字符凑不满一组"
                      % (len(text), width, len(text) % width))
    upper = alpha.isupper()
    out = bytearray()
    for i in range(0, len(text), width):
        chunk = text[i:i + width]
        v = 0
        for ch in chunk:
            c = ch.upper() if upper else ch
            if c not in alpha:
                return None, "含 %d 进制以外的字符：%r" % (radix, ch)
            v = v * radix + alpha.index(c)
        if v > 255:
            return None, "有一组的值 %d 超过 255，不像按字节分组" % v
        out.append(v)
    return bytes(out), None


# 「两位 base36 = 一字节」。和 base36 是两回事：
#   base36   把**整串**当一个大整数再转字节 → `6F4M57…` 解出来是垃圾
#   block36  每**两位**独立转一个字节   → `6F`=231=`E7`、`4M`=166=`A6`…
#            15 组正好 15 字节 → `离开的钥匙`
# 谜题里那种「看起来像 hex 但掺了 M/K/O/W」的串多半是它。
_B36_ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


@dec_name("block36", "b36x2")
def _d_block36(s):
    raw, err = blocks_to_bytes(re.sub(r"\s+", "", s).upper(), 2, 36)
    if raw is None:
        raise ValueError(err or "不是「两位 base36 = 一字节」的形式")
    return as_text(raw)


@enc_name("block36", "b36x2")
def _e_block36(s):
    return "".join(_B36_ALPHA[b // 36] + _B36_ALPHA[b % 36]
                   for b in as_bytes(s))


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


# ---------------------------------------------------------------- 文本转义（url / html / unicode / quoted-printable）

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


@enc_name("js", "jsescape")
def _e_js(s):
    return _e_unicode(s)


@dec_name("qp", "quotedprintable")
def _d_qp(s):
    import quopri
    return as_text(quopri.decodestring(s))


@enc_name("qp", "quotedprintable")
def _e_qp(s):
    import quopri
    return as_text(quopri.encodestring(as_bytes(s)))


# ------------------------------------------------- 字符替换（rot13 / rot47 / atbash）

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


@enc_name("rot47")
def _e_rot47(s):
    return _d_rot47(s)               # 同上


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


@enc_name("atbash")
def _e_atbash(s):
    return _d_atbash(s)              # 自反：解两次回到原文


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
# ★ 2026-10 按 benricho 的转录版逐项核对 別表第一号，修掉四处抄错：
#     キ 误作 `-..-..`（应 `-.-..`）、ト 误作 `..-`（应 `..-..`，因此和 ウ 撞码）、
#     （ 误作 `-.--.`（应 `-.--.-`，因此和 ル 撞码）、」整条缺失（应 `.-.-..`，段落）。
#   撞码是抄错造出来的假象，不是表本身的性质——原来那句「ト 与 ウ 同码、
#   两种读法都通顺」的注释，把一个数据错误当成了正常歧义，已删除。
#   修好之后表里没有真同码，但保留 `{A|B}` 机制：万一再撞码，宁可把选择权
#   交回给人，也不要静默取一个「语法通顺但意思全错」的答案。
WABUN = {
    "ア": "--.--", "イ": ".-", "ウ": "..-", "エ": "-.---", "オ": ".-...",
    "カ": ".-..", "キ": "-.-..", "ク": "...-", "ケ": "-.--", "コ": "----",
    "サ": "-.-.-", "シ": "--.-.", "ス": "---.-", "セ": ".---.", "ソ": "---.",
    "タ": "-.", "チ": "..-.", "ツ": ".--.", "テ": ".-.--", "ト": "..-..",
    "ナ": ".-.", "ニ": "-.-.", "ヌ": "....", "ネ": "--.-", "ノ": "..--",
    "ハ": "-...", "ヒ": "--..-", "フ": "--..", "ヘ": ".", "ホ": "-..",
    "マ": "-..-", "ミ": "..-.-", "ム": "-", "メ": "-...-", "モ": "-..-.",
    "ヤ": ".--", "ユ": "-..--", "ヨ": "--",
    "ラ": "...", "リ": "--.", "ル": "-.--.", "レ": "---", "ロ": ".-.-",
    "ワ": "-.-", "ヰ": ".-..-", "ヱ": ".--..", "ヲ": ".---", "ン": ".-.-.",
    "゛": "..", "゜": "..--.", "ー": ".--.-",
    "、": ".-.-.-", "」": ".-.-..", "（": "-.--.-", "）": ".-..-.",
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


# 和文モールス表按惯例用片假名书写（無線局運用規則別表もそう），但解出来的
# 日文用平假名更自然——歌词、台词、正文都是平假名混汉字。
#
# ★ 表本身必须保持片假名：浊音合并表 _WABUN_DAKU 是按片假名索引的，
#   中途转成平假名会让「シ + ゛ → ジ」直接失效。只在最终输出时转。
# ★ 不能简单地把整个片假名区 -0x60：长音符 ー(U+30FC) 减过去会变成 ゜，
#   繰り返し記号 ヽヾ 也会变成乱七八糟的东西。只转 ァ–ヶ（U+30A1–U+30F6）。
def _kata2hira(s):
    return "".join(chr(ord(c) - 0x60) if 0x30A1 <= ord(c) <= 0x30F6 else c
                   for c in s)


def _hira2kata(s):
    return "".join(chr(ord(c) + 0x60) if 0x3041 <= ord(c) <= 0x3096 else c
                   for c in s)


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
            "\n  [!] 有 %d 段在和文モールス表里查不到：\n"
            % len(unknown))
        for idx, seg in unknown:
            near = [k for k, v in WABUN.items() if _wabun_near(seg, v)]
            hint = ("；相近的有 " + " / ".join("%s=%s" % (k, WABUN[k]) for k in near[:3])) if near else ""
            sys.stderr.write("      第 %d 段  %s%s\n" % (idx, seg, hint))
        sys.stderr.write("\n")
    # 表是片假名，交出去的是平假名（日文正文的惯用写法）。
    # 要片假名用 `dec wabun --katakana`。
    return _kata2hira("".join(merged))


# 和文モールス只有 48 个大假名符号，没有小假名（ャュョッ）和 ヵヶ 的独立码，
# 一律按大假名送。所以 `ガッコウ` 编出来和 `ガツコウ` 一样，解回来也是后者——
# 这是体系本身的限制，不是往返 bug。
_WABUN_SMALL = {
    "ァ": "ア", "ィ": "イ", "ゥ": "ウ", "ェ": "エ", "ォ": "オ",
    "ャ": "ヤ", "ュ": "ユ", "ョ": "ヨ", "ッ": "ツ", "ヮ": "ワ",
    "ヵ": "カ", "ヶ": "ケ",
}


@enc_name("wabun", "wabunmorse")
def _e_wabun(s):
    """文字 → 和文モールス。平假名、片假名都收。

    浊音/半浊音在摩斯里不是一个符号，而是「清音 + ゛/゜」两个符号，
    所以编码时要反过来拆：ジ → シ + ゛。解码端再把它们粘回去。
    """
    rev_daku = {v: k for k, v in _WABUN_DAKU.items()}
    rev_han = {v: k for k, v in _WABUN_HANDAKU.items()}
    out = []
    for ch in _hira2kata(s):
        ch = _WABUN_SMALL.get(ch, ch)
        if ch in rev_daku:
            out.append(WABUN[rev_daku[ch]])
            out.append(WABUN["゛"])
        elif ch in rev_han:
            out.append(WABUN[rev_han[ch]])
            out.append(WABUN["゜"])
        elif ch in WABUN:
            out.append(WABUN[ch])
        elif ch in " 　\n\t":
            out.append("/")          # 词间分隔，解码端认
        else:
            raise ValueError("和文モールス表里没有这个字符：%r" % ch)
    return "/".join(out)


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


# ---------------------------------------------------------------- 压缩流与字符编码（zlib / uu / utf16 / utf32 / gbk）

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


@enc_name("gzip", "zlib", "bz2", "deflate", "inflate")
def _e_compress(s):
    # 解码端会轮流试 gzip/zlib/raw-deflate/bz2，所以编 gzip 就能被解回来
    return _bin_str(gzip.compress(as_bytes(s)))


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


@enc_name("uu")
def _e_uu(s):
    """标准 uuencode：begin 头 + 每行 ≤45 字节 + 长度 0 行 + end。"""
    data = as_bytes(s)
    lines = ["begin 644 data"]
    for i in range(0, len(data), 45):
        lines.append(binascii.b2a_uu(data[i:i + 45]).decode("ascii").rstrip("\n"))
    lines.append("`")
    lines.append("end")
    return "\n".join(lines)


@dec_name("utf16")
def _d_utf16(s):
    raw = raw_bytes(s)
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    raise ValueError("没有 BOM，不能确定字节序")


@enc_name("utf16")
def _e_utf16(s):
    return _bin_str(as_text(s).encode("utf-16"))      # 带 BOM


@dec_name("utf16be")
def _d_utf16be(s):
    raw = raw_bytes(s)
    return raw.decode("utf-16-be")


@enc_name("utf16be")
def _e_utf16be(s):
    return _bin_str(as_text(s).encode("utf-16-be"))


@dec_name("utf16le")
def _d_utf16le(s):
    raw = raw_bytes(s)
    return raw.decode("utf-16-le")


@enc_name("utf16le")
def _e_utf16le(s):
    return _bin_str(as_text(s).encode("utf-16-le"))


@dec_name("gbk")
def _d_gbk(s):
    return as_bytes(s).decode("gbk")


@enc_name("gbk")
def _e_gbk(s):
    return as_bytes(s).decode("gbk", "replace")


# ---------------------------------------------------------------- UTF-32
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


@enc_name("utf32")
def _e_utf32(s):
    return _bin_str(as_text(s).encode("utf-32"))


@dec_name("utf32be")
def _d_utf32be(s):
    return _u32_input(s).decode("utf-32-be")


@enc_name("utf32be")
def _e_utf32be(s):
    return _bin_str(as_text(s).encode("utf-32-be"))


@dec_name("utf32le")
def _d_utf32le(s):
    return _u32_input(s).decode("utf-32-le")


@enc_name("utf32le")
def _e_utf32le(s):
    return _bin_str(as_text(s).encode("utf-32-le"))


# ---------------------------------------------------------------- 乱码还原（mojibake）
#
# 「文件名乱码」那一类（`²âÊÔ` → 测试、`¼ªÏe` → 吉详）的自动还原还没定稿：
# 用户反馈其它例子解不出来，怀疑有误伤，先整体关掉，等拿到确定的样本再开。
#
# 这个开关同时控制三处：
#   1. mojibake_latin1()        —— 新增的「字节被当 Latin-1/CP1252」一类
#   2. _encode_back() 里的 NFC  —— NFD 形式的文件名（I + U+0308 这种）
#   3. auto_with_mojibake() 的兜底 —— 短串采信
#
# 代码全部保留，恢复只需把这个常量改成 True。
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


_ENABLE_LATIN1_MOJIBAKE = False


def _encode_back(s, enc):
    """把乱码字符串按 enc 还原成原始字节（含 CP936 的 0x80 ↔ € 特例）。

    ★ 先做 NFC 规范化，这不是洁癖：macOS 和不少工具按 **NFD** 存文件名，
    把 `Ï`(U+00CF) 拆成 `I`(U+0049) + `\u0308`（组合分音符），视觉上一模一样，
    但 `\u0308` 在任何单字节编码里都编不出来 —— 于是整个还原在第一步就报
    「'latin-1' codec can't encode character '\u0308'」，一个字节都没处理。
    实测文件名乱码 `¼ªÏê`（= 吉详）在 macOS 下就是这个形态。
    """
    if _ENABLE_LATIN1_MOJIBAKE:        # 见文件里的实验开关说明
        s = unicodedata.normalize("NFC", s)
    if enc not in _GBK_FAMILY or "\u20ac" not in s:
        return s.encode(enc)
    out = bytearray()
    for ch in s:
        if ch == "\u20ac":
            out.append(0x80)
        else:
            out += ch.encode(enc)
    return bytes(out)


# 粘贴进命令行、管道或网页输入框的文本，末尾很容易带上换行/空格。
# 而 UTF-8 严格解码对「末尾多一个字节」极其敏感：本来 38 字节只是
# 「结尾被截断」（unexpected end of data），多一个 \n 就变成
# 「非法续接字节」（invalid continuation byte）——症状完全不同，
# 很容易被误判成「数据本身损坏」，而实际只是多了个不可见字符。
# 只去 ASCII 空白：全角空格（U+3000）在乱码里可能是真数据，不能碰。
_MB_ASCII_SPACE = " \t\r\n\f\v"


def _mb_clean(s):
    """mojibake 所有入口的公共前置：去掉首尾 ASCII 空白。"""
    return s.strip(_MB_ASCII_SPACE)


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


def mojibake_latin1(s, min_plain=0.8):
    """「每个字符就是一个字节」那类乱码：整串都是西欧字符。

    文件名里最常见——Windows / 一些解压工具把 GBK 字节按西欧代码页显示，
    于是「测试」变成 `²âÊÔ`、「文件」变成 `ÎÄ¼þ`。

    和 mojibake_cross 互补，两者互不重叠：
      · cross 要求原文**以汉字为主**（输入端是「汉字乱码」：浣犲ソ、孨偼堦惗）
      · 这里要求原文**全在 Latin-1 范围**（输入端是「西欧字母乱码」：²âÊÔ）

    以前只做了 cross，所以 `²âÊÔ` 这种一个汉字都没有的乱码连门都进不去，
    自动识别直接报「数据可能损坏」——其实一个字节都没丢。

    门槛只有三条，都很硬：
      1. 所有字符 ≤ U+00FF（否则不可能是 latin-1 源）
      2. 严格 decode 成功（0 损失）
      3. 结果里**必须真的出现 CJK/假名**，否则只是把西欧字母换了个写法
    """
    if _ENABLE_LATIN1_MOJIBAKE:        # 同上，NFD 先合回预组合形式
        s = unicodedata.normalize("NFC", s)
    if len(s) < 2 or any(ord(c) > 0xFF for c in s):
        return []
    # ★ 这道门槛是防假阳性的关键：真正的「字节被当西欧代码页」是**成串**的
    #   （GBK 一个汉字 = 两个高位字符），而正常西欧文本只有零星几个变音字母。
    #   少了它，Müller → M黮ler、Señor → Se隳r、© 2026 → ｩ 2026 都会被"解"出来，
    #   比原文更糟。实测这三个都是这么冒出来的。
    high = sum(1 for c in s if ord(c) >= 0x80)
    if high < max(2, len(s) * 0.5):
        return []
    rows = []
    for src in ("cp1252", "latin-1"):
        try:
            raw = s.encode(src)
        except UnicodeEncodeError:
            continue
        for tgt in ("utf-8", "gb18030", "big5", "shift_jis", "euc-kr"):
            try:
                out = raw.decode(tgt)
            except (UnicodeDecodeError, LookupError):
                continue
            if out == s:
                continue
            # 结果至少要有 2 个 CJK/假名字符，否则只是换了个写法
            if sum(1 for c in out if ord(c) > 0x2FF) < 2:
                continue
            # 判据必须用 _common_ratio 而不是 _plain：b'\xb2\xe2\xca\xd4' 按
            # euc-kr 能解出 꿎桿，_plain 给满分 1.0（韩文都算可打印），
            # 但 _common_ratio 是 0.00（不是 GB2312 常用字、也不是假名）。
            # 用 _plain 排序会让韩文赢过正确的「测试」，实测就踩了这个坑。
            p = _common_ratio(out)
            if p >= min_plain:
                rows.append((p, src, tgt, out))
    rows.sort(key=lambda r: (-r[0], r[2]))
    return rows


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


def mojibake_split(s, min_plain=0.85, min_ok_ratio=0.5):
    """含 U+FFFD（字节已丢）的乱码：分段还原。

    谜题数据常常是「半路丢了几个字节」——从网页复制、OCR、聊天记录转存都会
    这样，缺失处显示成 `�`（U+FFFD）。这时候整段一起 encode 必定失败
    （U+FFFD 不在任何编码里），于是所有假设都被跳过，工具只能说「数据损坏」。

    但**缺失处两侧的字节是完好的**。切成几段分别还原，能救的部分全都救得回来，
    救不了的段原样留着。实测：

      崱傑偱慡偰� 偺壧偲夋柺偼堄枴偑偁� ... → 今まで全て� の歌と画面は意味があ� ...

    ★ 编码对取「能把最多段解成正常文字」的那一对，而不是每段各自猜——
      同一段乱码本来自同一对编码，逐段独立猜会拼出互相矛盾的版本。
    ★ 仍要求每段结果可读度 ≥min_plain，且成功段数占比 ≥min_ok_ratio，
      否则分段太短、假阳性会失控。

    返回 (结果, "源→目标", 成功段数, 非空段数) 或 None（不适用/没救出东西）。
    """
    if "\ufffd" not in s:
        return None
    # 准入门槛和跨编码一致，而且更严一点：分段之后每段都很短，假阳性特别容易
    # 出现。实测两条反例——正常中文 `正常中文�乱码` 被转成 `攣끽櫓匡�쫘쯤`、
    # 正常日文 `今まで全て� の歌` 被转成 `書まで畠て� の梧`。
    # 判据：原文得「像中日韩乱码」而不是「本来就正常」。
    if _han_ratio(s) < 0.5 or _common_ratio(s) > 0.35:
        return None
    parts = s.split("\ufffd")
    total = sum(1 for p in parts if p.strip())
    if total == 0:
        return None
    best = None
    for src in MOJIBAKE_ENCODINGS:
        for tgt in MOJIBAKE_TARGETS:
            if _same_encoding_family(src, tgt):
                continue
            outs = []
            ok = 0
            score = 0.0
            for p in parts:
                if not p.strip():
                    outs.append(None)    # 空段/纯空白：原样保留，不计入成功数
                    continue
                o = None
                try:
                    o = _encode_back(p, src).decode(tgt)
                except (UnicodeEncodeError, UnicodeDecodeError, LookupError):
                    o = None
                if o is not None and _plain(o) >= min_plain:
                    ok += 1
                    score += _plain(o)
                    outs.append(o)
                else:
                    outs.append(None)
            if ok == 0 or ok < total * min_ok_ratio:
                continue
            key = (ok, score)
            if best is None or key > best[0]:
                best = (key, src, tgt, list(outs))
    if best is None:
        return None
    (ok, _score), src, tgt, outs = best
    rendered = "\ufffd".join(p if o is None else o
                             for p, o in zip(parts, outs))
    return rendered, "%s→%s" % (src, tgt), ok, total


def mojibake_explicit(s, src, tgt):
    """显式指定「源编码→目标编码」的还原，不做任何猜测。

    自动路径摸不清时用它。典型：GBK 编的日文被当作 GBK 显示 = 这堆字，
    正确读法是 `--from gbk --to shift_jis`。
    """
    s = _mb_clean(s)
    # 含 U+FFFD 时整段必然编不回去（U+FFFD 不在任何编码里），但缺失处两侧的
    # 字节是好的：分段转，转不了的段原样留着。缺失位置用 ? 标出。
    if "\ufffd" in s:
        outs = []
        for part in s.split("\ufffd"):
            if not part:
                outs.append("")
                continue
            try:
                outs.append(_encode_back(part, src).decode(tgt))
            except (UnicodeEncodeError, UnicodeDecodeError, LookupError):
                outs.append(part)       # 这段救不了，原样留着
        return "\ufffd".join(outs)
    try:
        raw = _encode_back(s, src)
    except (UnicodeEncodeError, LookupError) as e:
        raise ValueError("按 %s 编回字节失败：%s（原文里有该编码表示不了的字符）" % (src, e))
    try:
        return raw.decode(tgt)
    except (UnicodeDecodeError, LookupError) as e:
        # 这条报错以前只有「N 字节解不开：<异常>」，使用者看到「invalid
        # continuation byte」只会以为是数据损坏。实际最常见的原因其实是
        # 粘贴时末尾多带了个换行——显式编码对逐字节对齐，多一个 \n 就报这个。
        raise ValueError(
            "%d 字节按 %s 解不开：%s\n"
            "两种常见原因，按顺序排查：\n"
            "  · 输入末尾多了空白（粘贴带的换行/空格）：显式编码对逐字节对齐，"
            "多一个 \\n 也会这样报，去掉再试\n"
            "  · 数据本身某处丢了字节：改用「最佳猜测」(--best) 或 --deep"
            % (len(raw), tgt, e))


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
    s = _mb_clean(s)
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
    # ---- 1.5 级：整串都是西欧字符 = 「字节被当 Latin-1」，此时上面两级
    # 都接不住（rank 目标是 UTF-8、cross 要求原文以汉字为主），必须单独一条。
    lat = mojibake_latin1(s) if _ENABLE_LATIN1_MOJIBAKE else []
    if lat:
        p, lsrc, ltgt, lout = lat[0]
        others = ["%s→%s(%s)" % (r[1], r[2], r[3]) for r in lat[1:3]]
        _hint(
            "\n  [西欧字符] 按 %s 编回字节、按 %s 解（可读度 %.0f%%）%s\n"
            % (lsrc, ltgt, p * 100,
               "；另有 " + "、".join(others) if others else ""))
        return lout

    # ---- 二级：换成非 UTF-8 的目标编码再试
    cross = mojibake_cross(s)
    if cross:
        p, cenc, ctgt, cout = cross[0]
        others = ["%s→%s" % (r[1], r[2]) for r in cross[1:]]
        _hint(
            "\n  [跨编码] 按 %s 编回字节、按 %s 解"
            "（可读度 %.0f%% → %.0f%%）%s\n"
            % (cenc, ctgt, _common_ratio(s) * 100, p * 100,
               "；另有等价解 " + "、".join(others[:3]) if others else ""))
        return cout
    # ---- 三级：输入本身含 U+FFFD（复制/转存时就丢了字节）。整段一起 encode
    # 必然失败（U+FFFD 不在任何编码里），但缺失处两侧的字节是完好的，
    # 分段还原能把能救的都救回来，而不是一句「数据损坏」了事。
    sp = mojibake_split(s)
    if sp:
        sout, pair, sok, stotal = sp
        _hint(
            "\n  [分段还原] 按 %s 解；原文有 %d 处字节缺失（输出里标 ?），"
            "成功还原 %d/%d 段\n"
            % (pair, s.count("\ufffd"), sok, stotal))
        return sout
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


def text_encoding_name(s):
    """给一段解出来的文本「贴个编码标签」，用于报告。

    为什么不能一律写 UTF-8：ASCII（0–127）在 UTF-8 里就是单字节原样表示，
    两者逐字节相同，`65 32 87` 解出的 `A W` 说 ASCII 更准确，说 UTF-8 也不算错
    但没信息量。相反，含非 ASCII 的文本（`你好`）就一定不是 ASCII，只能是
    UTF-8 / GBK 这类多字节编码。

    三种结果：
      · 纯 ASCII                        → "ASCII（与编码无关）"
      · 出现了 U+FFFD（非法序列被替换）  → "UTF-8（有乱码，字节非法）"
      · 其它                            → "UTF-8"

    ★ 纯 ASCII 为什么必须写「与编码无关」而不是干巴巴一个 "ASCII"：实测
      用户拿 `2W33342T` 问「convert 说 utf-8、auto 说 ASCII，可我当年是按
      GB18030 解的」——这三种说法全都不算错，因为 104/111/112/101 在 utf-8、
      gbk、gb18030、big5、shift_jis、ascii、latin-1 **七种编码下解出来一模
      一样**，都是 `hope`。报告写成一个编码名会被读成「工具认定了它 = 这个
      编码」，那是过度自信：纯 ASCII 时压根不存在「是哪种编码」这个问题。
    """
    if not s:
        return "UTF-8"
    if "\ufffd" in s:
        return "UTF-8（有替换符，字节非法）"
    if all(ord(c) < 128 for c in s):
        return "ASCII（与编码无关）"
    return "UTF-8"


def auto_with_mojibake(text, depth=3):
    """auto 的完整版：没找到可靠路径时，再认真试一次 mojibake。

    ★ 为什么单独包一层：`score()` 是为英文字母设计的，**中文越正常分越低**
      —— 实测 `测试` 97.0 < `²âÊÔ` 102.5，于是短串会被判成「越解越差」，
      auto 明明解出来了也不敢用。而文件名乱码普遍很短（`²âÊÔ`、`ÎÄ¼þ`），
      正好全落在这个坑里。所以 mojibake 的采信改用「常用字比例」。

    ★ 为什么必须共用：界面走的不是 `main()`，而是直接调 `auto()`。
      只在 main 里加兜底的话，界面上点「自动识别」仍然解不出来——这是实测
      踩过的，命令行能解、界面不能。

    返回 (score, 结果, 路径, 无)。
    """
    sc, final, path = auto(text, depth)
    # 零宽字符（U+200B/200C/200D/FEFF）从网页/文档复制时经常夹带进来，
    # 对纯 ASCII 数据来说它们只是噪音，却足以让所有识别规则失配 ——
    # 表现为「明明该是 base36/hex，auto 却说没有可靠路径，还给个 mojibake 提示」。
    # 先按原串试（万一是真正的零宽隐写），不行再剥掉重试。
    note = None
    if not (path and final != text) and re.search(r"[\u200b\u200c\u200d\ufeff]", text):
        stripped = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", text)
        if stripped != text:
            sc2, final2, path2 = auto(stripped, depth)
            if path2 and final2 != stripped:
                sc, final, path = sc2, final2, path2
                # ★ 不静默剥离：零宽字符也可能是**真隐写**（把信息藏在不可见
                #   字符里），闷头去掉就等于丢线索。B 站的富文本编辑器确实会
                #   插入 U+200C 防断行，但那要靠用户自己判断，工具只负责报数。
                note = ("原文含 %d 个零宽字符（U+200B/200C/200D/FEFF），"
                        "已剥离后再解——若是刻意藏的，请另行处理"
                        % (len(text) - len(stripped)))
    if not _ENABLE_LATIN1_MOJIBAKE:
        return sc, final, path, note    # 关掉时就是纯 auto()，行为不变
    if path and final != text:
        return sc, final, path, None
    try:
        mb = _d_mojibake(text)
    except Exception:
        mb = None
    if mb and mb != text and _common_ratio(mb) >= 0.8:
        return score(mb), mb, ["mojibake"], note
    return sc, final, path, note


def mojibake_best(s):
    """宽松还原：不管损失多大都返回最佳假设。

    用于「作者给的数据本身就是残缺的」这类谜题——这时候不存在"更原始的来源"，
    能做的只有把最可能的还原摊开、把缺失位置标成 ?，让人自己靠上下文补。
    返回 (结果, 损失率, 替换字符数, 编码名)。

    跨编码能无损解出时优先用它，此时损失率记 0、编码名写成 `源→目标`。
    """
    s = _mb_clean(s)
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
    # 三级：数据半路丢了字节（含 U+FFFD），整段转不了，分段救
    sp = mojibake_split(s)
    if sp:
        sout, pair, _sok, _stotal = sp
        lost = sout.count("\ufffd")
        return sout, lost / max(1, len(sout)), lost, pair + "(分段)"
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


def _mb_layer(s):
    """跑一层还原，返回 (损失率, 编码名, 结果)；一层都解不动时返回 None。

    从 mojibake_deep 的循环体里抽出来：分段还原时每一段都要跑同一套
    「先试 UTF-8 假设、不行再试中日韩跨编码」的顺序。
    """
    rows = mojibake_rank(s)
    # 一层 UTF-8 假设不成立时，这一层可能就是「中日韩编码互相误读」——
    # 不试的话 --deep 只会在原地打转，跑满 5 层仍然交回原文。
    cross = [] if (rows and rows[0][0] <= 0.02) else mojibake_cross(s)
    if rows and rows[0][0] <= 0.02:
        ratio, _bad, enc, out = rows[0]
        return ratio, enc, out
    if cross:
        _, cenc, ctgt, out = cross[0]
        return 0.0, "%s→%s" % (cenc, ctgt), out
    if rows:
        ratio, _bad, enc, out = rows[0]
        return ratio, enc, out
    return None


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
    cur = _mb_clean(s)
    layers = []
    # (可读率, 内容, 层号)
    best = (readability(cur), cur, 0)
    for n in range(1, max_rounds + 1):
        # 每层开头先看当前是否已经够用——阈值 0 时应当直接原样返回
        if readability(cur) * 100 >= lo:
            break
        if "\ufffd" in cur:
            # 当前文本含 U+FFFD，说明上一轮解码在某处丢了字节。
            # 这时候**不能整段编回去**：gb18030 也给 U+FFFD 留了编码位
            # （84 31 a4 37），整段转会把这条「此处无数据」的标记当成 4 个
            # 真实字节解出来，在正确答案后面拖一条垃圾尾巴——
            # 实测目标 `?迄今已有??余?` 被解成 `?迄今已有??余幄1?7`。
            # 按 U+FFFD 切段、各段分别还原，丢失位置原样保留。
            pieces, encs, ratios = [], [], []
            changed = False
            for seg in cur.split("\ufffd"):
                if not seg:
                    # 连续/结尾的 U+FFFD 会切出空段。跳过它们，否则 join
                    # 时会在结果末尾凭空多补一个分隔符（实测多出一个 ?）。
                    continue
                got = _mb_layer(seg)
                if got is None:
                    pieces.append(seg)          # 这一段救不了，原样留着
                    continue
                r, e, o = got
                if o != seg:
                    changed = True
                pieces.append(o)
                encs.append(e)
                ratios.append(r)
            if not changed:
                break
            out = "\ufffd".join(pieces)
            enc = ("分段还原(%s)" % "+".join(encs[:2])) if encs else "分段还原"
            ratio = max(ratios) if ratios else 0.0
        else:
            got = _mb_layer(cur)
            if got is None:
                break
            ratio, enc, out = got
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
    # 十进制 ASCII：`65 32 87 …` → "A W…"。三个硬条件：
    #   1. 数字之间**必须有分隔符** —— 裸数字串（`123456789`）是一个十进制数，
    #      不是字节序列，不加这条整串都会被当 ASCII 解；
    #   2. 每个数 ≤ 255 —— 日期 `2024 10 25` 第一个数就超了，自然被拒；
    #   3. 至少 3 个 —— 太短的（`1 2 3`）解出来是控制字符，由 acceptable() 兜住。
    _nums = re.findall(r"\d+", t)
    if (len(_nums) >= 3 and re.search(r"\d[\s,]+\d", t)
            and re.fullmatch(r"[\d\s,]+", t)
            and all(int(x) <= 255 for x in _nums)):
        cands.append("dec")
        # 八进制 ASCII：同一串数字若只由 0-7 组成，也可能是八进制
        # （`110 145 154 154 157` = Hello）。只含 0-7 时两个候选都放进去，
        # 让 acceptable() 用「解出来是不是可读文本」来分——`72 101 108` 这种
        # 含 8/9，进不了这条，只会是十进制。
        if (re.fullmatch(r"[0-7\s,]+", t)
                and all(int(x, 8) <= 255 for x in _nums)):
            cands.append("oct")
    if re.search(r"%[0-9A-Fa-f]{2}", t):
        cands.append("url")
    if re.search(r"&(#\d{1,7}|#x[0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});", t):
        cands.append("html")
    # \u4F60 / \u{1F600} / \xNN / U+4F60 / %u4F60 —— 全归 unicode 一族
    if re.search(r"\\u\{?[0-9a-fA-F]{4,6}\}?|\\x[0-9a-fA-F]{2}|U\+[0-9a-fA-F]{4,6}|%u[0-9a-fA-F]{4}", t):
        cands.append("unicode")

    # 进制/Base 系列靠"字符集 + 长度"约束，避免纯英文单词被误判
    body = compact.rstrip("=")
    # base32：字符集 A-Z2-7。长度校验**不能**要求「8 的倍数」——那是有 padding
    # 才成立的约束。去 padding 后的合法余数只有 0/2/4/5/7（1/3/6 是不可能的
    # 长度，对应字节数对不上）。实测 `MFXCAYLMORSXEIDFM5XQ`（20 字符 →
    # "an alter ego"）就因为 20 % 8 == 4 被挡在候选外，表现为
    # 「dec base32 能解、auto 却不行」。放宽后仍由 acceptable() 兜底，
    # 纯英文单词按 base32 解出来是垃圾，会被拒。
    if (re.fullmatch(r"[A-Z2-7]+=*", compact) and len(compact) >= 8
            and len(body) % 8 in (0, 2, 4, 5, 7)):
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
    # 两位 base36 = 一字节：`6F 4M 57` → E7 A6 BB → "离"。
    # 字符集是 0-9A-Za-z 全集，所以约束只能靠「偶数长度 + 每两位的值 ≤ 255」：
    # `6F`=231 ✓ 而纯 hex 串（`48656c6c6f`）两位一组也都 ≤ 255，
    # 所以必须排在 base16 之后——hex 能解出的东西会先被 hex 拿走。
    if (len(compact) % 2 == 0 and len(compact) >= 8
            and re.fullmatch(r"[0-9A-Za-z]+", compact)):
        try:
            if all(int(compact[i:i + 2], 36) <= 255
                   for i in range(0, len(compact), 2)):
                cands.append("block36")
        except ValueError:
            pass
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


def _cjk_only(s):
    """只留汉字。用来判断「这个变换到底动了什么」。"""
    return "".join(c for c in s if "\u4e00" <= c <= "\u9fff")


def brute(text, top=15):
    """所有编码都试，按可读性排序（这里才包含 rot13/rot47/atbash 这类模糊变换）。

    ★ 两处专治「乱码输入」的坑：

    1. mojibake 数据稍有残缺就抛 ValueError（损失率超标），而那个异常里其实
       **带着最佳猜测**。原来那一步 `except: continue` 等于把唯一能救它的
       解码器装看不见。现在失败时退到 mojibake_best 参与比较。

    2. rot13 / rot47 / atbash 只作用于 ASCII，汉字原样返回。当输入的汉字
       本身是乱码时，它们等于什么都没做，却仍能靠「全可打印 + 汉字占比」
       白拿 score() 给乱码汉字的底分（见 score 里那 0.3 系数）——
       实测 `鉑愮櫥褰曞悕…` 的 rot47 得 116.1 分，压过真正解出来的
       `?K?登录名：她的生日……`。这里对「CJK 完全没变且这些 CJK 是乱码」
       的结果降权。
    """
    names = list(DECODERS) + ["rot13", "rot47", "atbash"]
    cjk_in = _cjk_only(text)
    cjk_in_is_garbage = len(cjk_in) >= 4 and _common_ratio(cjk_in) < 0.5
    results = []
    for name in names:
        if name == "braillebits":
            continue
        fn = DECODERS.get(name)
        if not fn:
            continue
        partial = False
        try:
            out = fn(text)
        except Exception:
            # 判据只看**汉字部分**是否乱码，不能看整串：`_common_ratio` 把
            # ASCII（含空白）也算作正常字符，输入末尾多一个换行就能把比例从
            # 0.488 顶到 0.500，正好踩过阈值——实测「末尾带 \n 的同一串」
            # 因此被 continue 掉，mojibake 整个不参与比较，rot47 又爬回第一。
            if name != "mojibake" or not cjk_in_is_garbage:
                continue
            try:
                out, _r, _b, _e = mojibake_best(text)
                partial = True
            except Exception:
                continue
        if not out or out == text:
            continue
        if not isinstance(out, str):
            out = as_text(out)
        if partial:
            # U+FFFD 在这里的意思是「这个位置原始字节丢了」，不是「解错了」。
            # score() 对替换符有 300 分/n 的重罚（防乱码靠"可打印"虚高），
            # 直接算会把唯一能救的结果压到 70 分、排到最后——和 UI 一样先换成
            # `?` 再打分，让缺失处只体现"不可读一个字符"，不否定整个还原。
            out = out.replace("\ufffd", "?")
        if not acceptable(out, 0.25):
            continue
        sc = score(out)
        if partial:
            # 有缺失处的结果打个折：能无损解出的候选应该排在它前面。
            sc -= 3.0
        # 只轮换 ASCII、汉字原样保留 —— 而这些汉字本来就是乱码，等于白做。
        if cjk_in_is_garbage and _cjk_only(out) == cjk_in:
            sc -= 20.0
        results.append((sc, name + ("(缺字)" if partial else ""), out))
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


# 各编码的「合理最小输出长度比例」，供 auto 的长度骤减保护使用。
# 默认 0.1（中文 base64 约 25%，安全）；位流类天生压缩得狠，必须单独放宽：
#   bin: 8 位 → 1 字节，中文再 3 字节 → 1 字符，合计 24:1（4.2%），取 0.03 留余量
MIN_OUT_RATIO = {
    "bin": 0.03,
}


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
        #
        # ★ 但阈值不能一刀切：位流类天生压缩得狠。bin 是 8 位→1 字节，
        #   再叠加 UTF-8 中文 3 字节→1 字符，合起来是 24:1（4.2%）。
        #   实测一道 363 字符的 0/1 流正确解出 16 个汉字，却因为 4.4% < 10%
        #   被当成「信息丢失」丢掉，auto 报「没有可靠的编码路径」。
        min_ratio = MIN_OUT_RATIO.get(name, 0.1)
        if len(text) >= 8 and len(out) < max(2, len(text) * min_ratio):
            continue
        sub_sc, final, path = auto(out, depth - 1, _memo)
        cand = sub_sc + bonus
        if cand > best[0] + 1e-9:
            best = (cand, final, [name] + path)
    _memo[key] = best
    return best


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


# ------------------------------------------------- 编码 × 进制（convert）
#
# 把「字符编码」和「进制表示」当成两个正交的维度。现有的 hex/bin/dec/oct/block36
# 其实都是「某个进制 + UTF-8」的特例，但编码名把它们压成了一维，于是同一批字节
# 换个字符编码就得另想办法。这里把它拆开：
#
#   文本 ←字符编码→ 字节 ←进制表示→ "228 189 160" / "E4BDA0" / "11100100…"
#
# 定宽进制（2/16/36）直接按固定位宽切，分隔符可有可无；变长进制（8/10）必须
# 有分隔符 —— 否则 `111` 分不清是一个数还是三个数。

_RADIX_FIXED = {2: 8, 16: 2, 36: 2}     # 进制 -> 每字节占几个字符

# 解码时按这个顺序试，前面的更常见；auto 只在这些里挑。
CONVERT_ENCODINGS = ["utf-8", "gbk", "gb18030", "big5", "shift_jis", "ascii", "latin-1"]


# 各进制允许的内容字符（分隔符另算）。用来把「含非法字符」和「位数/范围
# 不对」分开报——否则 `41g 42` 会被报成「位数是奇数（5）」，把用户引到完全
# 错误的方向（实际原因是那个 g）。
_RADIX_CHARS = {
    2:  "01",
    8:  "01234567",
    10: "0123456789",
    16: "0123456789abcdefABCDEF",
    36: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
}
_RADIX_LABEL = {2: "二进制", 8: "八进制", 10: "十进制", 16: "十六进制", 36: "base36"}

# 分隔符：空白优先，其余是抄数据时常见的几种。`-` 放在最后（放中间会被
# 当成字符范围，`re.error: bad character range`——踩过）。
_RADIX_SEP = re.compile(r"[\s,;:.\-]")


def _radix_clean(text, radix):
    """去掉前缀和分隔符，留下真正的数位内容。"""
    t = text.strip()
    if radix == 16:
        t = re.sub(r"(0[xX]|\\x)", "", t)
    elif radix == 2:
        t = re.sub(r"(0[bB])(?=[01])", "", t)
    return _RADIX_SEP.sub("", t)


def _radix_bad_chars(s, radix):
    """返回不在该进制字符集里的字符（去重、保序）。"""
    allowed = _RADIX_CHARS.get(radix, "")
    bad = []
    for c in s:
        if c not in allowed and c not in bad:
            bad.append(c)
    return bad


def radix_to_bytes(text, radix):
    """把「按某个进制表示的字节」解析回 bytes。返回 (bytes, 错误说明)。

    ★ 顺序很重要：**先校验字符集，再查长度和范围**。反过来就会出现
      `41g 42` 报「十六进制位数是奇数（5）」、`65 abc 66` 报「多个数之间必须
      有空格或逗号」（可输入里明明有空格）、`2W!3334` 报「base36 位数是奇数」
      ——三例的报错都指向了假原因，真正的问题都是混进了一个非法字符。
    """
    t = text.strip()
    if not t:
        return None, "没有输入"
    if radix not in _RADIX_CHARS:
        return None, "不支持的进制：%s" % radix
    s = _radix_clean(t, radix)
    if not s:
        return None, "没有%s的数位" % _RADIX_LABEL[radix]
    bad = _radix_bad_chars(s, radix)
    if bad:
        return None, "含%s以外的字符：%s" % (
            _RADIX_LABEL[radix],
            " ".join(repr(c) for c in bad[:6]) + ("…" if len(bad) > 6 else ""))
    if radix == 16:
        if len(s) % 2:
            return None, "十六进制位数是奇数（%d），每两位表示一个字节" % len(s)
        return bytes.fromhex(s), None
    if radix == 2:
        if len(s) % 8:
            return None, "二进制位数 %d 不是 8 的倍数，每 8 位表示一个字节" % len(s)
        return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8)), None
    if radix == 36:
        s = s.upper()
        if len(s) % 2:
            return None, "base36 位数是奇数（%d），每两位表示一个字节" % len(s)
        vals = [int(s[i:i + 2], 36) for i in range(0, len(s), 2)]
        if any(v > 255 for v in vals):
            return None, "有两位组的值超过 255，不像是按字节分组的 base36"
        return bytes(vals), None
    # 8 / 10：变长，一个数一个字节
    nums = re.findall(r"\d+", t)
    if len(nums) == 1 and len(s) > 3 and int(s, radix) > 255:
        # 整串被当成一个数了。不这么说用户会以为「值超范围」，其实是缺分隔符。
        return None, ("%d 进制是变长的，多个数之间必须有空格或逗号——现在整串"
                      "被当成一个数 %s" % (radix, s[:12] + ("…" if len(s) > 12 else "")))
    vals = [int(x, radix) for x in nums]
    over = [v for v in vals if v > 255]
    if over:
        return None, "有数超过 255（如 %d），一个数只能表示一个字节" % over[0]
    return bytes(vals), None


def encoding_candidates(raw):
    """列出能**完整**解出这些字节的编码，按 CONVERT_ENCODINGS 的顺序。

    ★ 为什么排除 latin-1：它对**任意**字节流都合法（逐字节映射到 U+0000–U+00FF），
      恒真所以毫无信息量。放进候选里，任何乱码都会「同时合法于 latin-1」，
      提示立刻变成噪音。它只在别的全失败时当兜底，见 bytes_to_text。

    ★ 纯 ASCII 走捷径：这类字节在所有 ASCII 兼容编码下逐字节相同，所以**解一次
      就够**，没必要六个编码各跑一遍。480 KB 输入实测 6.4 ms → 0.1 ms（约 120 倍）。
      结论本来就不需要靠解码得出，不该为它付六次 decode 的钱。
    """
    cands = [e for e in CONVERT_ENCODINGS if e != "latin-1"]
    if raw.isascii():
        text = raw.decode("ascii")
        return [(e, text) for e in cands]
    out = []
    for enc in cands:
        try:
            out.append((enc, raw.decode(enc)))
        except (UnicodeDecodeError, LookupError):
            continue
    return out


def bytes_to_text(raw, encoding="auto"):
    """bytes -> 文本。返回 (文本, 实际用的编码, 说明)。

    ★ encoding="auto" 的语义是「我替你挑一个」，**不是**「这批字节就是它」。
      两者差别很大：同一串字节常常有多种编码都能完整解出（纯 ASCII 时七种
      全行），甚至解出**不同**的话。所以这里不再闷头返回第一个成功的编码，
      而是把所有候选扫一遍，能解出不同结果时把话说清楚，让用户自己定。
    """
    if encoding and encoding != "auto":
        try:
            return raw.decode(encoding), encoding, None
        except UnicodeDecodeError as e:
            return None, encoding, ("这些字节不是合法的 %s：%s" % (encoding, e))
        except LookupError:
            return None, encoding, "不认识的编码名：%s" % encoding
    # auto：按常见程度依次试，要求**整个字节流合法**（不做 replace，
    # 否则任何字节都能"解出来"，等于没判断）
    cands = encoding_candidates(raw)
    if not cands:
        # 连 utf-8/gbk/gb18030/big5/shift_jis/ascii 全都不合法，只剩 latin-1
        # 这个「什么都能装」的兜底。解得出字不代表对，必须说清。
        try:
            return raw.decode("latin-1"), "latin-1", \
                ("这些字节不是任何常见多字节编码的合法序列，只能按 Latin-1 "
                 "逐字节映射——解出来多半是乱码，更可能是原始字节已经损坏")
        except Exception:
            return raw.decode("utf-8", "replace"), "utf-8(有替换符)", \
                "没有任何一种常见编码能完整解出这些字节，结果里的 ? 是替换符"
    if raw.isascii():
        # 纯 ASCII：所有 ASCII 兼容编码逐字节相同，报哪个名字都没区别。
        # 报 ascii（最精确的那个下界），并把「其实谁都能解」说出来。
        also = [e for e, _ in cands if e != "ascii"]
        note = None
        if also:
            note = ("字节全部 < 128，是纯 ASCII —— %s 解出来完全一样，"
                    "「是哪种编码」在这里没有意义" % " / ".join(also))
        return cands[0][1], "ascii", note
    text, enc = cands[0][1], cands[0][0]
    # 有非 ASCII 字节时，候选之间**解出不同文本**才有歧义（utf-8 与 gbk
    # 对同一批中文通常互斥，真撞上了就必须让用户自己选）。
    #
    # ★ 但「能解出不同东西」不等于「值得摆出来」：GB 系的字节常常同时是合法
    #   的 Big5，于是每段 GB 中文都会附赠一串纯属巧合的胡话（实测
    #   `离开的钥匙跃迁的线索…` 用 big5 读成 `燭羲腔埥啻埲ヮ腔盄坰帤眭腔…`）。
    #   把胡话当平等候选列出来，只会逼用户去做一次没有意义的判断。所以用
    #   _common_ratio（像正常文字的字符占比）过滤，只留看着也像人话的替代。
    base = _common_ratio(text)
    floor = max(0.6 * base, 0.5)
    diff = [(e, t) for e, t in cands[1:]
            if t != text and _common_ratio(t) >= floor]
    note = None
    if diff:
        note = ("这批字节也能完整解成别的东西，结果不同：%s —— 用 --encoding "
                "指定当年用的那种" % "；".join(
                    "%s → %s" % (e, t[:20]) for e, t in diff))
    return text, enc, note


def convert_decode(text, radix=16, encoding="auto"):
    """编码 × 进制 组合解码。返回 dict（给 CLI 和界面共用）。"""
    # 和 auto 一样，先剥零宽字符（U+200B/200C/200D/FEFF）。从网页/文档复制
    # 带进来的这些字符肉眼不可见，但会直接让「按字符集解析」失败——实测用户
    # 那段 base36 每行夹了 10 个 U+200C，`convert` 直接报「含 base36 以外的
    # 字符」，而 auto 因为剥了零宽所以能解。
    _zw = len(re.findall(r"[\u200b\u200c\u200d\ufeff]", text))
    text = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", text)
    raw, err = radix_to_bytes(text, int(radix))
    if raw is None:
        return {"ok": False, "error": err}
    if not raw:
        return {"ok": False, "error": "解出来是空的"}
    out, enc, warn = bytes_to_text(raw, encoding)
    if out is None:
        return {"ok": False, "error": warn, "bytes": list(raw)}
    res = {"ok": True, "result": out, "encoding": enc, "bytes": list(raw),
           "warning": warn,
           # 「字符编码：utf-8」会被读成「这批字节就是 UTF-8」——auto 只是挑了个
           # 能解的。把归属写进返回值，CLI 和界面共用一份措辞，免得两边各写一句
           # 以后又对不上（这正是用户报「convert 说 utf-8、auto 说 ASCII」的成因）。
           "how": ("auto → " if (encoding or "auto") == "auto" else "") + enc}
    if _zw:
        res["zw"] = ("原文含 %d 个零宽字符，已剥离——若是刻意藏的，请另行处理" % _zw)
    return res


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
    global _QUIET
    argv = sys.argv[1:]
    quiet = "-q" in argv or "--quiet" in argv
    _QUIET = quiet
    best = "--best" in argv
    # 和文モールス表是片假名，但默认输出平假名；--katakana 保留片假名
    katakana = "--katakana" in argv
    argv = [a for a in argv
            if a not in ("-q", "--quiet", "--best", "--katakana")]
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
    # convert 用：--radix <2|8|10|16|36> / --encoding <utf-8|gbk|ascii…|auto>
    # codec 的 main 是手写解析（没有通用 opt），照 --depth 的模式来。
    # 短选项和 `blocks` 对齐（那边一直是 -r）：同一个「块按进制转字节」的
    # 概念用两套写法，从 blocks 挪过来的人必然踩空——实测我自己就先踩了。
    radix_opt = 16
    for flag in ("--radix", "-r"):
        if flag in argv:
            i = argv.index(flag)
            if i + 1 >= len(argv):
                print("%s 后面要跟一个进制（2/8/10/16/36）" % flag)
                return 2
            radix_opt = int(argv[i + 1])
            argv = argv[:i] + argv[i + 2:]
            break
    enc_opt = "auto"
    for flag in ("--encoding", "-e"):
        if flag in argv:
            i = argv.index(flag)
            if i + 1 >= len(argv):
                print("%s 后面要跟一个编码名（如 utf-8 / gbk / auto）" % flag)
                return 2
            enc_opt = argv[i + 1]
            argv = argv[:i] + argv[i + 2:]
            break

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
        sc, final, path, auto_note = auto_with_mojibake(text, depth)
        if quiet:
            print(final)
            return 0
        # stdout 只放结果、stderr 放分析：界面上两者分处「结果」框和底部提示条，
        # 命令行里看起来仍连在一起。
        sys.stdout.flush()
        sys.stderr.write("原始：%s\n" % (
            text[:120] + ("…" if len(text) > 120 else "")))
        if path:
            # 路径 + 得分 + 输出编码：三样一起给，省得用户猜
            #「这串到底是用什么解出来的、解出来又按什么编码变成的文本」。
            sys.stderr.write("路径：%s\n得分：%.1f\n输出编码：%s\n"
                             % (" → ".join(path), sc, text_encoding_name(final)))
            if auto_note:
                sys.stderr.write("[注意] %s\n" % auto_note)
            print(final)
        else:
            # 还原尝试已经由 auto_with_mojibake 做过了，走到这里是真的没辙
            sys.stderr.write("没有可靠的编码路径（原样输出）\n")
            # 只说「没有可靠路径」等于什么都没说：用户分不清是「这压根不是编码」
            # 还是「是乱码但数据坏了」。这里再探一次 mojibake，把损失率亮出来。
            try:
                mb_out, mb_ratio, mb_bad, mb_enc = mojibake_best(text)
            except Exception:
                mb_ratio = 0.0
            if 0 < mb_ratio <= 0.6:
                # 多行乱码要逐行缩进：只缩进第一行的话，后面几行会顶格，
                # 和上面的「原始：」糊成一片，看不出这段是提示的一部分。
                # 不折叠：提示本来就没几行，省两行换来一句「还有 N 行没显示」
                # 纯属添乱，而且下一行又会再叫一次 --best，同一件事说两遍。
                lines = mb_out.replace("\ufffd", "?").splitlines() or [""]
                body = "\n".join("    " + ln[:120] for ln in lines)
                # stdout 带缓冲、stderr 不带，不 flush 的话提示会窜到上面去
                sys.stdout.flush()
                sys.stderr.write(
                    "\n  [提示] 最接近的是 mojibake（假设 %s，损失 %.1f%%，%d 处缺失）：\n"
                    "%s\n"
                    "  数据本身可能有损坏。使用 `dec mojibake --best` 查看完整信息。\n"
                    % (mb_enc, mb_ratio * 100, mb_bad, body))
            # 原文照样进 stdout：`auto x > out.txt` 不能产出空文件。
            print(final)
        return 0

    if cmd == "convert":
        # 编码 × 进制 组合解码。和 `dec hex` 那套的区别：那几个把字符编码
        # 写死成 UTF-8，这里可以显式指定（同一批字节换 GBK 就是另一句话）。
        radix, enc = radix_opt, enc_opt
        text, _ = read_input(argv[1:])
        res = convert_decode(text, radix, enc)
        if not res["ok"]:
            sys.stderr.write("失败：%s\n" % res["error"])
            if res.get("bytes"):
                sys.stderr.write("  解析出的字节：%s\n" % res["bytes"][:32])
            return 1
        if not quiet:
            # 「字符编码：utf-8」会被读成「这批字节就是 UTF-8」——而 auto 只是
            # 挑了个能解的。措辞统一由 convert_decode 的 how 给出。
            sys.stderr.write("进制：%d　字符编码：%s　字节数：%d\n"
                             % (radix, res["how"], len(res["bytes"])))
            if res.get("warning"):
                sys.stderr.write("  [提示] %s\n" % res["warning"])
            if res.get("zw"):
                sys.stderr.write("  [注意] %s\n" % res["zw"])
            sys.stdout.flush()
        print(res["result"])
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
        b, err = blocks_to_bytes(text, width, radix)
        if b is None:
            print("无法按 width=%d radix=%d 解析：%s" % (width, radix, err))
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
            _hint(
                "\n  [显式] 按 %s 编回字节 → 按 %s 解%s\n"
                % (src, tgt,
                   "（未指定的那一侧用了默认值）" if not (mb_from and mb_to) else ""))
            print(out)
            return 0
        # dec mojibake --best：谜题里数据本身残缺时，强制给出最佳猜测，
        # 缺失处标 ?，并把损失率告诉使用者。
        if cmd.startswith("dec") and name == "mojibake" and best:
            out, ratio, bad, enc = mojibake_best(text)
            print(out.replace("\ufffd", "?"))
            # _hint 里会先 flush stdout，所以下面的提示不会跑到结果前面
            if "(分段)" in enc:
                _hint(
                    "\n  [分段还原] 按 %s 解；原文 %d 处字节缺失\n"
                    % (enc.replace("(分段)", "").replace("\u2192", " 编回字节、按 "),
                       bad))
            elif "\u2192" in enc:
                # 跨编码无损解出：enc 形如 gb18030→shift_jis
                _hint(
                    "\n  [跨编码] 按 %s 解，完整无损\n"
                    % enc.replace("\u2192", " 编回字节、按 "))
            elif ratio > 0:
                _hint(
                    "\n  [提示] 损失 %.1f%%（%d 处缺失，假设 %s）\n"
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
                    _hint(
                        "  第 %d 层  %-12s 损失 %5.1f%%  可读率 %3.0f%%%s\n"
                        % (n, enc, ratio * 100, rd * 100,
                           "  ←采信" if n == used else ""))
            _hint(
                "  采信第 %d 层（可读率 %.0f%%，阈值 %d%%）%s\n\n"
                % (used, readability(out) * 100, deep,
                   "；残片若仍乱，可能是混合层数，需手工切段" if layers else ""))
            print(out.replace("\ufffd", "?"))
            sys.stdout.flush()
            return 0
        fn = table.get(name)
        if not fn:
            print("不支持的编码：%s（使用 `codec.py list` 查看全部编码）" % name)
            return 2
        try:
            out = fn(text)
        except Exception as e:
            print("失败：%s" % e)
            return 1
        # 和文モールス默认输出平假名；--katakana 转回片假名方便对照原表
        if katakana and name in ("wabun", "wabunmorse") and isinstance(out, str):
            out = _hira2kata(out)
        print(out)
        return 0

    print("未知子命令：%s" % cmd)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
