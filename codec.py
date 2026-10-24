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

例：
  codec.py auto 'S1VWRVIgTEFOR1VBR0U='
  codec.py brute '&#x4f60;&#x597d;'
  codec.py dec base58 '2NEpo7TZRRrLZSi2U'
  codec.py enc hex --file /bin/ls | head
  codec.py dec mojibake --best '瀹跺涵鐘跺喌'
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
    raw = s.encode("latin-1", "ignore") if all(ord(c) < 256 for c in s) else as_bytes(s)
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
    return as_text(binascii.a2b_uu(s.split("\n")[0]))


@dec_name("utf16")
def _d_utf16(s):
    raw = as_bytes(s)
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    raise ValueError("没有 BOM，不能确定字节序")


@dec_name("utf16be")
def _d_utf16be(s):
    raw = as_bytes(s)
    return raw.decode("utf-16-be")


@dec_name("utf16le")
def _d_utf16le(s):
    raw = as_bytes(s)
    return raw.decode("utf-16-le")


# ---- UTF-32：每码点 4 字节。CTF 里常见形态是「每码点 8 位 hex」：
#      00000023 = '#'、00007ED9 = '给'、00004E86 = '了'
#      判别要点：hex 长度是 8 的倍数，且多数码点带大片前导零。
def _u32_input(s):
    """UTF-32 的输入可能是 hex 串，也可能已是裸字节。"""
    t = re.sub(r"\s+", "", s)
    if len(t) >= 8 and len(t) % 8 == 0 and re.fullmatch(r"[0-9a-fA-F]+", t):
        return bytes.fromhex(t)
    return as_bytes(s)


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
            raw = s.encode(enc)          # 严格：不在该编码里的字符直接判该假设失败
        except (UnicodeEncodeError, LookupError):
            continue
        out = raw.decode("utf-8", errors="replace")
        bad = out.count("\ufffd")
        rows.append((bad / max(1, len(out)), bad, enc, out))
    rows.sort()
    return rows


@dec_name("mojibake", "garbled", "乱码")
def _d_mojibake(s):
    """UTF-8 被当成 GBK / Big5 / Latin-1 读过的还原（如「浜哄彧」→「人只」）。"""
    if all(ord(c) < 128 for c in s):
        raise ValueError("纯 ASCII，不可能是 UTF-8 被误读的结果")
    rows = mojibake_rank(s)
    if not rows:
        raise ValueError("没有可用的反编码假设")
    ratio, bad, enc, out = rows[0]
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
            "还原损失 %.1f%%（%d 个替换字符，假设 %s），原始字节流可能有缺失。\n"
            "\n"
            "  最佳猜测（? = 缺失处，不可全信）：\n"
            "%s"
            % (ratio * 100, bad, enc, body))
    return out


def mojibake_best(s):
    """宽松还原：不管损失多大都返回最佳假设。

    用于「作者给的数据本身就是残缺的」这类谜题——这时候不存在"更原始的来源"，
    能做的只有把最可能的还原摊开、把缺失位置标成 ?，让人自己靠上下文补。
    返回 (结果, 损失率, 替换字符数, 编码名)。
    """
    rows = mojibake_rank(s)
    if not rows:
        raise ValueError("没有可用的反编码假设")
    ratio, bad, enc, out = rows[0]
    return out, ratio, bad, enc


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

    if re.search(r"[\u2800-\u28ff]", t):
        cands.append("braille")
    if re.fullmatch(r"[.\-\u00b7\u2022\u2014\u2013\u2212_\s/|]{4,}", t):
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
        path = args[idx + 1]
        with open(path, "rb") as fh:
            data = fh.read()
        args = args[:idx] + args[idx + 2:]
        # want_bytes 用于 enc hex / enc base64 这类"把原始字节转成文本表示"的场景。
        # 不加这个开关，二进制文件会先被 as_text 用 U+FFFD 替换掉，
        # 输出的 hex 根本不是文件的真实字节。
        return (data if want_bytes else as_text(data)), args
    rest = [a for a in args if not a.startswith("-")]
    return " ".join(rest), args


def main():
    argv = sys.argv[1:]
    quiet = "-q" in argv or "--quiet" in argv
    best = "--best" in argv
    argv = [a for a in argv if a not in ("-q", "--quiet", "--best")]
    depth = 3
    for flag in ("--depth", "-d"):
        if flag in argv:
            i = argv.index(flag)
            depth = int(argv[i + 1])
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
        # dec mojibake --best：谜题里数据本身残缺时，强制给出最佳猜测，
        # 缺失处标 ?，并把损失率告诉使用者。
        if cmd.startswith("dec") and name == "mojibake" and best:
            out, ratio, bad, enc = mojibake_best(text)
            print(out.replace("\ufffd", "?"))
            # stdout 带缓冲、stderr 不带，不 flush 的话提示会跑到结果前面
            sys.stdout.flush()
            if ratio > 0:
                sys.stderr.write(
                    "\n  [提示] 损失 %.1f%%（%d 处缺失，假设 %s）；? 处需要靠上下文猜\n"
                    % (ratio * 100, bad, enc))
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
