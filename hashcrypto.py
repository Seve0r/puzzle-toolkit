#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
哈希、现代密码与常见密码学。

子命令：
  identify <hash>                  猜测哈希类型（长度/字符集/前缀）
  hash <algo> <text>               计算；algo 见 `hash -h` 里的列表
  crack <hash> [--algo A] [--wordlist F] [--rules]
                                   字典爆破。不给 algo 自动识别
  xor <data> [--key HEX | --key-str TEXT]
                                   单字节全试 / 指定 key / 多字节自动
  repeat-xor <file>                检测重复密钥 XOR 并尝试还原密钥
  aes --key HEX [--iv HEX] [--mode cbc|ecb|ctr|gcm] <base64|hex>
                                   解密（--enc 加密）。GCM 密文格式为
                                   ciphertext||tag，加密时自动追加 16 字节 tag
  rc4 --key TEXT <data>            RC4
  rsa --n N --e E [--c C] [--d D]  RSA 解密与常见攻击
  jwt <token>                      解析 JWT；--crack 尝试爆破 HS256 密钥
  list                             列出识别的哈希类型

通用：--hex 输入是 hex，默认按文本；-f/--file FILE 从文件读输入（路径支持 ~）；
-q 只输出结果
"""
import sys
import os
import re
import json
import base64
import hashlib
import hmac
import binascii
import struct
import itertools
import math

# ------------------------------------------------------------------ 哈希识别

HASH_SIGNS = [
    # (名称, 长度, 正则, 说明)
    ("md5", 32, r"^[a-f0-9]{32}$", "32 位十六进制"),
    ("md4", 32, r"^[a-f0-9]{32}$", "与 md5 同形"),
    ("ntlm", 32, r"^[a-f0-9]{32}$", "Windows NTLM"),
    ("md5(md5)", 32, r"^[a-f0-9]{32}$", ""),
    ("sha1", 40, r"^[a-f0-9]{40}$", "40 位十六进制"),
    ("sha224", 56, r"^[a-f0-9]{56}$", ""),
    ("sha256", 64, r"^[a-f0-9]{64}$", "64 位十六进制"),
    ("sha3-256", 64, r"^[a-f0-9]{64}$", "与 sha256 同形"),
    ("sha384", 96, r"^[a-f0-9]{96}$", ""),
    ("sha512", 128, r"^[a-f0-9]{128}$", "128 位十六进制"),
    ("crc32", 8, r"^[a-f0-9]{8}$", "太短，碰撞多"),
    ("md5-16", 16, r"^[a-f0-9]{16}$",
     "老式「16 位 MD5」= 32 位 MD5 的第 9~24 个字符；也可能是 MySQL 4.1 之前的 hash"),
    ("bcrypt", None, r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt"),
    ("md5crypt", None, r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$", "Linux md5crypt"),
    ("sha512crypt", None, r"^\$6\$", "Linux sha512crypt"),
    ("sha256crypt", None, r"^\$5\$", "Linux sha256crypt"),
    ("argon2", None, r"^\$argon2", "Argon2"),
    ("django", None, r"^pbkdf2_sha256\$", "Django"),
    ("mysql41", None, r"^\*[A-F0-9]{40}$", "MySQL 4.1+"),
    ("sha1-base64", 28, r"^[A-Za-z0-9+/]{27}=$", "28 位 base64 = sha1"),
    ("md5-base64", 24, r"^[A-Za-z0-9+/]{22}==$", "24 位 base64 = md5"),
    ("base64", None, r"^[A-Za-z0-9+/]{12,}={0,2}$", "可能就是 base64"),
]

HASHLIB_ALGOS = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s",
]


def identify(h):
    h = h.strip()
    hits = []
    for name, length, pat, note in HASH_SIGNS:
        if length is not None and len(h) != length:
            continue
        # ★ 必须大小写不敏感：哈希的十六进制大小写是随机的，而签名表里的
        #   正则全是小写 `[a-f0-9]`。不加这个标志的话，`098F6BCD…` 会一路
        #   漏到最后的 base64 规则上，表现为「大写 MD5 认不出来、小写就认得」。
        if not re.match(pat, h, re.IGNORECASE):
            continue
        if name == "base64":
            # 光看字符集不够 —— 任何十六进制串都满足 base64 的字符集，
            # 于是每条哈希后面都跟着一条误导性的「可能就是 base64」。
            # 解出来大部分不是可打印字符的，就不算。
            try:
                raw = base64.b64decode(h + "=" * (-len(h) % 4))
                ok = sum(1 for b in raw if 32 <= b < 127 or b in b"\r\n\t")
                if ok / max(1, len(raw)) < 0.85:
                    continue
            except Exception:
                continue
        hits.append((name, note))
    if not hits:
        # 字符集兜底
        if re.fullmatch(r"[A-Za-z0-9+/=]+", h):
            hits.append(("base64?", "纯 base64 字符集"))
        elif re.fullmatch(r"[a-f0-9A-F]+", h):
            hits.append(("未知十六进制", "长度不在常见值"))
        else:
            hits.append(("未知", ""))
    return hits


# ------------------------------------------------------------------ 弱密码表

COMMON_PASSWORDS = """
123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon
123123 baseball abc123 football monkey letmein 696969 shadow master 666666
qwertyuiop 123321 mustang 1234567890 michael 654321 superman 1qaz2wsx 7777777
121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh
hunter buster soccer harley batman andrew tigger sunshine iloveyou 2000
charlie robert thomas hockey ranger daniel starwars klaster 112233 george
computer michelle jessica pepper 1111 zxcvbn 555555 11111111 131313 freedom
777777 pass maggie 159753 aaaaaa ginger princess joshua cheese amanda summer
love ashley 6969 nicole chelsea biteme matthew access yankees 987654321
dallas austin thunder taylor matrix william corvette hello martin heather
secret fucker merlin diamond 1234qwer gfhjkm hammer silver 222222 88888888
anthony justin test bailey q1w2e3r4t5 patrick internet scooter orange 11111
golfer cookie richard samantha bigdog guitar jackson whatever mickey chicken
sparky snoopy maverick phoenix camaro sexy peanut morgan welcome falcon cowboy
ferrari samsung andrea smokey steelers joseph mercedes dakota arsenal eagles
melissa boomer booboo spider nascar monster tigers yellow xxxxxx 123123123
gateway marina diablo bulldog qwer1234 compaq purple banana junior hannah
123654 porsche lakers iceman money cowboys 987654 london tennis 999999
admin root toor letmein1 password1 password123 admin123 root123 test123
qwerty123 1q2w3e4r 1q2w3e zaq12wsx qazxsw asdf1234 zxcv1234 iloveyou1
princess1 sunshine1 football1 baseball1 superman1 starwars1 whatever1
welcome1 hello123 abc12345 a1b2c3d4 changeme default temp 12345678910
qwertyui asdfghjkl zxcvbnm1 passw0rd p@ssw0rd P@ssw0rd  Pa$$w0rd 
""".split()


def candidates(wordlist=None, rules=False):
    seen = set()

    def emit(w):
        w = w.strip()
        if w and w not in seen:
            seen.add(w)
            return w
        return None

    srcs = []
    if wordlist:
        with open(wordlist, encoding="utf-8", errors="ignore") as f:
            srcs = [l.rstrip("\n") for l in f]
    else:
        srcs = list(COMMON_PASSWORDS)
        # 字典爆破要的是覆盖面，所以系统大词典优先（十万量级）；
        # Windows 上没有 /usr/share/dict，退回随仓库分发的 data/words.txt。
        # 想用 rockyou 之类的专用字典，直接 --wordlist 指定。
        here = os.path.dirname(os.path.abspath(__file__))
        for p in (
            os.environ.get("PUZZLE_WORDLIST", ""),
            "/usr/share/dict/words",
            "/usr/share/dict/american-english",
            "/usr/share/dict/british-english",
            "/usr/local/share/dict/words",
            os.path.join(here, "data", "words.txt"),
            os.path.join(here, "..", "data", "words.txt"),
        ):
            if not p or not os.path.exists(p):
                continue
            try:
                with open(p, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        w = line.strip()
                        if not w.isalpha() or len(w) > 12:
                            continue
                        srcs.append(w)
                        lw = w.lower()
                        if lw != w:
                            # 系统词典里是 English / Secret 这种首字母大写，
                            # 而真实密码多半写全小写，两种都要试。
                            srcs.append(lw)
            except Exception:
                continue
            break

    for w in srcs:
        v = emit(w)
        if v:
            yield v
        if rules:
            variants = [
                w.lower(), w.upper(), w.capitalize(),
                w + "1", w + "123", w + "!", w + "2024", w + "2025", w + "2026",
                w[::-1], w + w,
            ]
            for v2 in variants:
                g = emit(v2)
                if g:
                    yield g
        # 纯数字补零变体
        if w.isdigit():
            for suf in ("0", "00", "1", "12", "123"):
                g = emit(w + suf)
                if g:
                    yield g


def md4(data):
    """OpenSSL 3 移除了 md4，hashlib.new('md4') 直接报错，NTLM 只能自己实现。"""
    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    def rol(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    ml = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    idx1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    sh1 = [3, 7, 11, 19] * 4
    idx2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    sh2 = [3, 5, 9, 13] * 4
    idx3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    sh3 = [3, 9, 11, 15] * 4

    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", msg[off:off + 64])
        a, b, c, d = A, B, C, D
        for i in range(16):
            if i % 4 == 0:
                a = rol((a + F(b, c, d) + X[idx1[i]]) & 0xFFFFFFFF, sh1[i])
            elif i % 4 == 1:
                d = rol((d + F(a, b, c) + X[idx1[i]]) & 0xFFFFFFFF, sh1[i])
            elif i % 4 == 2:
                c = rol((c + F(d, a, b) + X[idx1[i]]) & 0xFFFFFFFF, sh1[i])
            else:
                b = rol((b + F(c, d, a) + X[idx1[i]]) & 0xFFFFFFFF, sh1[i])
        for i in range(16):
            v = (X[idx2[i]] + 0x5A827999) & 0xFFFFFFFF
            if i % 4 == 0:
                a = rol((a + G(b, c, d) + v) & 0xFFFFFFFF, sh2[i])
            elif i % 4 == 1:
                d = rol((d + G(a, b, c) + v) & 0xFFFFFFFF, sh2[i])
            elif i % 4 == 2:
                c = rol((c + G(d, a, b) + v) & 0xFFFFFFFF, sh2[i])
            else:
                b = rol((b + G(c, d, a) + v) & 0xFFFFFFFF, sh2[i])
        for i in range(16):
            v = (X[idx3[i]] + 0x6ED9EBA1) & 0xFFFFFFFF
            if i % 4 == 0:
                a = rol((a + H(b, c, d) + v) & 0xFFFFFFFF, sh3[i])
            elif i % 4 == 1:
                d = rol((d + H(a, b, c) + v) & 0xFFFFFFFF, sh3[i])
            elif i % 4 == 2:
                c = rol((c + H(d, a, b) + v) & 0xFFFFFFFF, sh3[i])
            else:
                b = rol((b + H(c, d, a) + v) & 0xFFFFFFFF, sh3[i])
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF
    return struct.pack("<4I", A, B, C, D)


def compute(algo, data):
    a = algo.lower().replace("-", "_")
    if a == "ntlm":
        return md4(data.encode("utf-16le")).hex()
    if a == "md4":
        # 不能指望 hashlib.new("md4")：OpenSSL 3 默认把 md4 划进 legacy provider，
        # 直接抛 unsupported hash type，于是 md4 明明识别得出来却永远破不了。
        return md4(data.encode()).hex()
    if a in ("md5(md5)", "md5_md5"):
        return hashlib.md5(hashlib.md5(data.encode()).digest()).hexdigest()
    if a in ("mysql", "mysql41"):
        s1 = hashlib.sha1(data.encode()).digest()
        return "*" + hashlib.sha1(s1).hexdigest().upper()
    if a == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    try:
        return hashlib.new(a, data.encode()).hexdigest()
    except Exception:
        return None


def crack(target, algo=None, wordlist=None, rules=False):
    target = target.strip()
    algos = [algo] if algo else [
        n for n, _, _, _ in HASH_SIGNS
        if n in HASHLIB_ALGOS or n in ("ntlm", "md4", "md5(md5)")
    ]
    algos = [a for a in dict.fromkeys(algos) if a]
    tried = set()
    for w in candidates(wordlist, rules):
        for a in algos:
            key = (a, w)
            if key in tried:
                continue
            tried.add(key)
            h = compute(a, w)
            if h and h.lower() == target.lower():
                return a, w
    return None, None


# ------------------------------------------------------------------ XOR

def printable_ratio(b):
    if not b:
        return 0.0
    ok = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return ok / len(b)


def score_bytes(b):
    """给 XOR 结果排序。

    只看可打印率是不够的：XOR 任意 key 都可能产出"全可打印"的垃圾，
    实测 b'BOFFE\n]EXFN' 和 b'hello world' 并列满分。必须再加字母占比、
    空格占比和常见二字母组的权重，才能把真正的明文顶上来。
    """
    r = printable_ratio(b)
    if r < 0.6:
        return r
    try:
        t = b.decode("utf-8")
    except Exception:
        return r
    if not t:
        return r
    n = len(t)
    letters = sum(1 for c in t if c.isalpha()) / n
    spaces = t.count(" ") / n
    low = t.lower()
    big = sum(low.count(w) for w in ("th", "he", "in", "er", "an", "re", "on", "at", "en", "nd"))
    words = sum(low.count(w) for w in (" the ", " and ", " you ", "ing", "tion", " is ", " of "))
    return r + letters * 0.8 + spaces * 2.0 + big * 0.05 + words * 0.3


def xor_single(data):
    results = []
    for k in range(256):
        out = bytes(c ^ k for c in data)
        results.append((score_bytes(out), k, out))
    results.sort(key=lambda x: -x[0])
    return results


def xor_key(data, key):
    if not key:
        raise ValueError("key 不能为空")
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def xor_repeat_detect(data, maxkey=32):
    """重复密钥 XOR：按汉明距离找密钥长度"""
    def hamming(a, b):
        return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

    best = []
    for kl in range(2, maxkey + 1):
        blocks = [data[i * kl:(i + 1) * kl] for i in range(4)]
        if len(blocks) < 4 or any(len(b) != kl for b in blocks):
            break
        d = sum(hamming(blocks[i], blocks[i + 1]) for i in range(3)) / (3.0 * kl)
        best.append((d, kl))
    best.sort()
    # 不要把"是某个更小候选整数倍"的长度排除掉——真长度常常排在它自己的约数后面
    # （6 位密钥时 3 位的汉明距离可能更小），一排除就永远找不到正确答案。
    # 改成全部试一遍，靠"明文可读性 - 长度惩罚"选：约数解出的明文只有一半对，
    # 分数自然低；倍数（12/18）会被长度惩罚压住。
    picked = [kl for _, kl in best[:8]]
    results = []
    for kl in picked:
        cols = [bytes(data[i] for i in range(j, len(data), kl)) for j in range(kl)]
        key = bytes(max(xor_single(c), key=lambda x: x[0])[1] for c in cols)
        # 逐列独立恢复偶尔会错一两个字节（那一列碰巧没有区分度），
        # 用整段明文的可读性对密钥做坐标下降修正。
        key, sc = _refine_xor_key(data, key)
        # 密钥是周期的（ICEICEIC → ICE）就收敛，别报个重复串
        k2 = _key_period(key)
        if k2 != key:
            pt2 = xor_key(data, k2)
            if score_bytes(pt2) >= sc * 0.97:
                key, sc = k2, score_bytes(pt2)
        results.append((sc - 0.15 * len(key), key, xor_key(data, key)))
    results.sort(key=lambda x: -x[0])
    return results


def _key_period(k):
    n = len(k)
    for p in range(1, n + 1):
        if n % p == 0 and k == k[:p] * (n // p):
            return k[:p]
    return k


def _refine_xor_key(data, key, rounds=3):
    """一个字节错了会连带影响整段明文的可读性，单轮坐标下降往往修不干净，
    要反复扫到不再有改进为止。"""
    k = bytearray(key)
    best = score_bytes(xor_key(data, bytes(k)))
    for _ in range(rounds):
        improved = False
        for i in range(len(k)):
            keep = k[i]
            for cand in range(256):
                if cand == keep:
                    continue
                k[i] = cand
                sc = score_bytes(xor_key(data, bytes(k)))
                if sc > best + 1e-9:
                    best = sc
                    keep = cand
                    improved = True
            k[i] = keep
        if not improved:
            break
    return bytes(k), best


# ------------------------------------------------------------------ AES / RC4

def _pad(b, bs=16, block=True):
    if not block:
        return b
    n = bs - len(b) % bs
    return b + bytes([n]) * n


def _unpad(b, block=True):
    if not block or not b:
        return b
    n = b[-1]
    if 1 <= n <= 16 and b[-n:] == bytes([n]) * n:
        return b[:-n]
    return b


def aes_run(data, key, mode="cbc", iv=None, enc=False, tag=None):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception as e:
        raise RuntimeError("需要 cryptography 库：%s" % e)
    mode = mode.lower()
    bs = 16
    padded = mode in ("ecb", "cbc")
    if padded:
        data = _pad(data, bs, True) if enc else data
    if mode == "ecb":
        m = modes.ECB()
    elif mode == "cbc":
        m = modes.CBC(iv or b"\x00" * 16)
    elif mode == "ctr":
        m = modes.CTR(iv or b"\x00" * 16)
    elif mode == "gcm":
        giv = iv or b"\x00" * 12
        if enc:
            m = modes.GCM(giv)
        else:
            # GCM 解密必须带 tag，否则 finalize() 直接抛
            # "Authentication tag must be provided when decrypting"。
            # 约定：密文 = ciphertext || tag（末尾 16 字节），加密时按这个格式输出。
            if tag is None:
                if len(data) < 17:
                    raise ValueError("GCM 密文太短，取不出末尾 16 字节的 tag")
                tag = data[-16:]
                data = data[:-16]
            m = modes.GCM(giv, tag)
    else:
        raise ValueError("不支持的 mode：%s" % mode)
    c = Cipher(algorithms.AES(key), m)
    op = c.encryptor() if enc else c.decryptor()
    out = op.update(data) + op.finalize()
    if mode == "gcm":
        # GCM 是流模式，本来就没有填充，绝不能去 unpad
        return out + op.tag if enc else out
    if not enc and padded:
        out = _unpad(out, True)
    return out


def rc4(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for c in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


# ------------------------------------------------------------------ RSA

def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def pollard_rho(n):
    if n % 2 == 0:
        return 2
    import random
    while True:
        x = random.randrange(2, n)
        y = x
        c = random.randrange(1, n)
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def factor(n, tries=3):
    if is_prime(n):
        return n, n
    for _ in range(tries):
        try:
            p = pollard_rho(n)
            if p and p not in (1, n):
                return p, n // p
        except Exception:
            continue
    # Fermat：p、q 接近时有效。改成时间上限而不是固定 10 万次——
    # p/q 不接近时，多跑的那几万次覆盖的差值区间小到可以忽略，
    # 只是让 rsa 子命令白白卡住（大 n 上每次 isqrt 都不便宜）。
    import time
    deadline = time.time() + 1.0
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    while time.time() < deadline:
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, "big") if i else b""


def rsa_attack(n, e, c=None):
    log = []
    # 1. 直接分解
    pq = factor(n)
    if pq and pq[0] not in (1, n):
        p, q = pq
        log.append("分解成功：p=%d q=%d" % (p, q))
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
            log.append("d = %d" % d)
            if c is not None:
                m = pow(c, d, n)
                log.append("明文(整数) = %d" % m)
                try:
                    log.append("明文(bytes) = %r" % int_to_bytes(m))
                except Exception:
                    pass
            return log
        except Exception as ex:
            log.append("求 d 失败：%s" % ex)
    # 2. 小 e 且无填充
    if c is not None and e <= 5:
        for k in range(1, 100000):
            m, exact = _iroot(c + k * n, e)
            if exact:
                log.append("小 e 开方成功（k=%d）" % k)
                log.append("明文 = %r" % int_to_bytes(m))
                return log
    if not log:
        log.append("没有直接突破口，试试共模攻击 / Wiener（需要额外参数）")
    return log


def _iroot(x, k):
    """整数 k 次方根，返回 (root, exact)。

    不能用 x ** (1.0 / k)：float 只有 53 位精度，几十位就开不准，
    实测 50 位的数已经 exact=False，200 位直接 OverflowError。
    RSA 里的 c + k*n 动辄几百位，所以必须走整数二分。
    """
    if x < 0:
        return 0, False
    if x == 0:
        return 0, True
    if k == 1:
        return x, True
    if k == 2:
        r = math.isqrt(x)
        return r, r * r == x
    # 上界取 2 的若干次方，保证 hi**k > x
    lo, hi = 1, 1 << ((x.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** k == x


def rsa_wiener(n, e):
    """d 很小（d < n^0.25）时，e/n 的连分数收敛就是 k/d"""
    def cf(a, b):
        while b:
            q = a // b
            yield q
            a, b = b, a - q * b

    def convs(seq):
        p0, p1 = 0, 1
        q0, q1 = 1, 0
        for a in seq:
            p0, p1 = p1, a * p1 + p0
            q0, q1 = q1, a * q1 + q0
            yield p1, q1

    for k, d in convs(cf(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        t = math.isqrt(disc)
        if t * t == disc and (s + t) % 2 == 0:
            return d, (s + t) // 2, (s - t) // 2
    return None


# ------------------------------------------------------------------ JWT

def b64u_dec(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64u_enc(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def jwt_parse(tok):
    parts = tok.strip().split(".")
    if len(parts) < 2:
        raise ValueError("不是 JWT（应有 3 段）")
    hdr = json.loads(b64u_dec(parts[0]))
    pay = json.loads(b64u_dec(parts[1]))
    return hdr, pay, parts


def jwt_crack(tok, wordlist=None):
    parts = tok.strip().split(".")
    if len(parts) != 3:
        raise ValueError("需要完整 3 段 JWT")
    hdr = json.loads(b64u_dec(parts[0]))
    alg = str(hdr.get("alg", "")).upper()
    hf = {"HS256": hashlib.sha256,
          "HS384": hashlib.sha384,
          "HS512": hashlib.sha512}.get(alg)
    if hf is None:
        # 硬编码 sha256 的话，HS384/HS512 的 token 会一直"爆不出来"，
        # 用户会误以为是密钥太强，其实是算法选错了。
        raise ValueError("只支持 HS256 / HS384 / HS512，这个 token 的 alg=%r" % (hdr.get("alg"),))
    signing_input = (parts[0] + "." + parts[1]).encode()
    target = b64u_dec(parts[2])
    for w in candidates(wordlist, rules=True):
        if hmac.new(w.encode(), signing_input, hf).digest() == target:
            return w
    return None


# ------------------------------------------------------------------ CLI

def die(msg, code=2):
    print(msg)
    sys.exit(code)


# ---------------------------------------------------------------- 按格式穷举

# hashcat 风格的掩码字符集
MASK_SETS = {
    "?d": "0123456789",
    "?l": "abcdefghijklmnopqrstuvwxyz",
    "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "?a": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "?h": "0123456789abcdef",
    "?H": "0123456789ABCDEF",
    "?s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}

CHARSET_ALIAS = {
    "digits": "?d", "num": "?d", "数字": "?d",
    "lower": "?l", "loweralpha": "?l", "小写": "?l",
    "upper": "?u", "upperalpha": "?u", "大写": "?u",
    "alnum": "?a", "alnumlower": "?l", "hex": "?h",
    "汉字": "?d",
}


def parse_mask(mask):
    """把 `?d?d?d?d` 解析成每个位置的字符集列表。`??` 是字面问号。"""
    out = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            nxt = mask[i + 1]
            key = "?" + nxt
            if key in MASK_SETS:
                out.append(MASK_SETS[key])
                i += 2
                continue
            if nxt == "?":                 # ?? -> 字面问号
                out.append("?")
                i += 2
                continue
        out.append(mask[i])                # 字面字符
        i += 1
    return out


def chase_match(h, target):
    """判断算出来的哈希是否命中目标。

    ★ 目标可能只有 16 位 —— 那是老式「16 位 MD5」，实际是 32 位 MD5 的
      第 9~24 个字符。穷举时照样算完整 MD5、只截中间比对，难度完全不变
      （决定破解成本的是明文空间，不是哈希长度）。
    """
    t = target.strip().lower()
    if len(t) == 16 and len(h) == 32:
        return h[8:24] == t
    if len(t) == len(h):
        return h == t
    return t in h


def _brute_worker(job):
    """扫一块 head，命中就返回 (明文, 完整哈希)，扫完没有返回 None。

    ★ 这里不用 multiprocessing.Event 来「找到一个就通知大家停」：Event 不能
      通过 Pool 的 pickle 传进子进程（会报 Condition objects should only be
      shared between processes through inheritance）。改成主进程拿到第一个结果
      后直接 pool.terminate() 杀掉其余进程，效果一样还更干脆。
    """
    heads, tails, prefix, suffix, algo, target = job
    import hashlib as _h
    import itertools as _it
    for head in heads:
        head_s = "".join(head)
        if not tails:
            cand = prefix + head_s + suffix
            hs = _h.new(algo, cand.encode("utf-8", "surrogateescape")).hexdigest()
            if chase_match(hs, target):
                return cand, hs
            continue
        # ★ product() 返回的是一次性迭代器，必须**每个 head 重新创建**。
        #   放到循环外的话只有第一个 head 能遍历完，其余全被跳过 ——
        #   症状是「跑得飞快但什么都没找到」，非常容易误判成没命中。
        for tail in _it.product(*tails):
            cand = prefix + head_s + "".join(tail) + suffix
            hs = _h.new(algo, cand.encode("utf-8", "surrogateescape")).hexdigest()
            if chase_match(hs, target):
                return cand, hs
    return None


def brute_force(target, mask, algo="md5", threads=None, prefix="", suffix=""):
    """按掩码穷举。返回 (明文, 完整哈希) 或 None。

    多进程：把掩码切成「前 k 位 × 后 n-k 位」，前 k 位的所有组合摊给各进程，
    每个进程在自己那份里遍历后 n-k 位。这样避免了每个候选都做一次
    「索引 → 字符串」的转换（那会让速度掉一半以上）。
    """
    import multiprocessing as mp
    import itertools as _it

    charsets = parse_mask(mask)
    if not charsets:
        raise ValueError("掩码为空")
    total = 1
    for cs in charsets:
        total *= len(cs)
    if threads is None:
        threads = os.cpu_count() or 4
    threads = max(1, min(threads, total))

    # 选切分点：让每个进程分到几十份，负载才匀
    split = 1
    while split < len(charsets):
        heads_n = 1
        for cs in charsets[:split + 1]:
            heads_n *= len(cs)
        if heads_n >= threads * 4:
            break
        split += 1
    head_space = list(_it.product(*charsets[:split]))
    tails = charsets[split:]

    # 把 head_space 均分成 threads 份
    chunks = []
    step = max(1, (len(head_space) + threads - 1) // threads)
    for i in range(0, len(head_space), step):
        chunks.append(head_space[i:i + step])

    ctx = mp.get_context()
    jobs = [(c, tails, prefix, suffix, algo, target) for c in chunks if c]

    found = None
    pool = ctx.Pool(len(jobs))
    try:
        for r in pool.imap_unordered(_brute_worker, jobs):
            if r:
                found = r
                break
    finally:
        pool.terminate()      # 找到了就别让其余进程继续白跑
        pool.join()
    return found


def main():
    argv = sys.argv[1:]
    quiet = "-q" in argv or "--quiet" in argv
    argv = [a for a in argv if a not in ("-q", "--quiet")]
    hexin = "--hex" in argv
    argv = [a for a in argv if a != "--hex"]
    enc = "--enc" in argv or "-e" in argv
    argv = [a for a in argv if a not in ("--enc", "-e")]
    rules = "--rules" in argv
    argv = [a for a in argv if a != "--rules"]

    def opt(name, cast=str, default=None):
        nonlocal argv
        if name in argv:
            i = argv.index(name)
            v = cast(argv[i + 1])
            argv = argv[:i] + argv[i + 2:]
            return v
        return default

    mask_opt = opt("--mask", str, None)
    charset_opt = opt("--charset", str, None)
    len_opt = opt("--len", int, None)
    threads_opt = opt("--threads", int, None)
    prefix_opt = opt("--prefix", str, "")
    suffix_opt = opt("--suffix", str, "")

    mode = opt("--mode", str, "cbc")
    algo = opt("--algo", str, None)
    wordlist = opt("--wordlist", str, None)
    key_hex = opt("--key", str, None)
    key_str = opt("--key-str", str, None)
    iv_hex = opt("--iv", str, None)
    n_opt = opt("--n", int, None)
    e_opt = opt("--e", int, None)
    c_opt = opt("--c", int, None)
    d_opt = opt("--d", int, None)

    # -f / --file：从文件读输入。README 的「通用选项」表一直写着「适用全部」，
    # 但这里从来没实现过——`-f` 会被当成数据的一部分静默吃掉。
    # 内容作为一个整体参数追加到末尾，进入下面的 rest。
    if "-f" in argv or "--file" in argv:
        i = argv.index("-f") if "-f" in argv else argv.index("--file")
        if i + 1 >= len(argv):
            raise SystemExit("错误：-f/--file 后面要跟文件路径")
        path = os.path.expanduser(argv[i + 1])
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
        argv = argv[:i] + argv[i + 2:] + [data.decode("utf-8", "replace")]

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0

    cmd = argv[0]
    rest = argv[1:]

    if cmd == "list":
        for name, length, pat, note in HASH_SIGNS:
            print("  %-14s %-6s %s" % (name, length or "-", note))
        return 0

    if cmd == "identify":
        if not rest:
            die("缺少哈希")
        for name, note in identify(rest[0]):
            print("  %-14s %s" % (name, note))
        return 0

    if cmd == "hash":
        if len(rest) < 2:
            die("用法：hash <algo> <text>")
        h = compute(rest[0], " ".join(rest[1:]))
        if not h:
            die("不支持的算法：%s\n可选：%s" % (rest[0], ", ".join(HASHLIB_ALGOS + ["ntlm", "mysql"])))
        print(h)
        return 0

    if cmd == "crack":
        if not rest:
            die("缺少哈希")
        h = rest[0].strip()
        a, w = crack(h, algo, wordlist, rules)
        if a:
            print("破解成功：%s = %s" % (a, w))
        else:
            print("没在字典里找到（试过 %s）" % (algo or "自动识别的算法"))
        return 0

    if cmd == "mask":
        if len(argv) < 2 or "-h" in argv or "--help" in argv:
            print("用法：hashcrypto.py mask <哈希> --mask \"?d?d?d?d\" [--algo md5]")
            print("      或 mask <哈希> --len 8 --charset digits")
            print()
            print("掩码字符集：?d 数字  ?l 小写  ?u 大写  ?a 大小写+数字  ?h hex")
            print("           ?? 字面问号，其它字符按字面算")
            print("--prefix / --suffix  在候选前后追加固定串（如生日前缀 19）")
            print("--threads N          进程数，默认用满所有核心")
            return 2
        target = argv[1]
        mask = mask_opt
        if mask is None:
            if not len_opt:
                print("要给出 --mask，或者同时给 --len（和可选的 --charset）")
                return 2
            key = CHARSET_ALIAS.get((charset_opt or "digits").lower(),
                                    charset_opt or "?d")
            mask = (key if key in MASK_SETS else key) * len_opt if key in MASK_SETS \
                else (charset_opt or "0123456789") * len_opt
        algo = opt("--algo", str, None)
        if algo is None:
            algo = {16: "md5", 32: "md5", 40: "sha1", 64: "sha256"}.get(len(target), "md5")
        try:
            import time as _t
            t0 = _t.time()
            hit = brute_force(target, mask, algo=algo, threads=threads_opt,
                              prefix=prefix_opt, suffix=suffix_opt)
            dt = _t.time() - t0
        except Exception as e:
            print("失败：%s" % e)
            return 1
        if not hit:
            print("没找到（掩码 %s，算法 %s，用时 %.1f 秒）" % (mask, algo, dt))
            return 1
        cand, full = hit
        print("找到：%s" % cand)
        print("  %s(%s) = %s" % (algo, cand, full))
        if len(target) == 16:
            print("  目标只有 16 位，比对的是中间 16 位：%s" % full[8:24])
        print("  用时 %.2f 秒" % dt)
        return 0

    if cmd == "xor":
        if not rest:
            die("缺少数据")
        data = bytes.fromhex(rest[0]) if hexin else rest[0].encode()
        if key_str is not None:
            # 显式文本 key，绕开下面那条 hex 自动判断
            print(xor_key(data, key_str.encode()).decode("utf-8", "replace"))
            return 0
        if key_hex:
            is_hexish = bool(re.fullmatch(r"[0-9a-fA-F]+", key_hex)) and len(key_hex) % 2 == 0
            if is_hexish:
                # "abcd" 这种既是合法 hex 又是常见文本 key，默认按 hex 走，
                # 但要说一声——不然用户永远想不通为什么 key 不对。
                sys.stderr.write(
                    "[提示] --key %r 全部是 hex 字符，已按十六进制解析成 %r。"
                    "本意若是文本 key，请用 --key-str\n"
                    % (key_hex, bytes.fromhex(key_hex)))
            kb = bytes.fromhex(key_hex) if is_hexish else key_hex.encode()
            print(xor_key(data, kb).decode("utf-8", "replace"))
            return 0
        rows = xor_single(data)
        if quiet:
            print(rows[0][2].decode("utf-8", "replace"))
            return 0
        print("单字节 XOR 前 10：")
        for sc, k, out in rows[:10]:
            print("  key=0x%02x %6.2f  %r" % (k, sc, out[:70]))
        # --help 里承诺了「多字节自动」，但这里原先直接 return 了，实际只做单字节。
        # 补上：单字节全都解不成话时，再按重复密钥分析一次。
        # 阈值 4.0 是经验值——正常英文的 score_bytes 一般 3.5 以上，
        # 全乱码则都在 2.x；长度不足 32 时汉明距离统计不可靠，不做。
        best_single = rows[0][0]
        if best_single < 4.0 and len(data) >= 32:
            multi = xor_repeat_detect(data)
            if multi and multi[0][0] > best_single + 0.3:
                print("\n多字节重复密钥 XOR（单字节解不成立，自动延伸）：")
                for sc, k, out in multi[:5]:
                    print("  key=%-16r %6.2f" % (k, sc))
                    print("    %r" % out[:100])
        return 0

    if cmd == "repeat-xor":
        if not rest:
            die("缺少文件或 hex")
        if os.path.exists(rest[0]):
            data = open(rest[0], "rb").read()
            # 文件里可能是原始密文，也可能是 hex 文本——Cryptopals 那类题目几乎
            # 都给 hex 文件。若按二进制处理，解出来是一串乱码、还看不出原因。
            # 这里先判断一次：纯 hex 字符（允许空白）且长度为偶数，就按 hex 解。
            body = re.sub(rb"\s+", b"", data.strip())
            if len(body) >= 16 and len(body) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+", body):
                try:
                    data = bytes.fromhex(body.decode())
                except ValueError:
                    pass
        else:
            data = bytes.fromhex(rest[0])
        rows = xor_repeat_detect(data)
        for sc, key, pt in rows[:5]:
            print("  key=%-16r %6.2f" % (key, sc))
            print("    %r" % pt[:100])
        return 0

    if cmd in ("aes", "rc4"):
        if not rest or not key_hex:
            die("用法：%s --key KEY [--iv HEX] [--mode cbc] <data>  （加密输出 hex，解密输入 hex）" % cmd)
        raw = rest[0]
        if enc:
            # 加密方向：输入按**文本**理解，除非显式 --hex
            data = bytes.fromhex(raw) if hexin else raw.encode()
        else:
            # 解密方向：优先当 hex，其次 base64
            if hexin or (re.fullmatch(r"[0-9a-fA-F]+", raw) and len(raw) % 2 == 0):
                data = bytes.fromhex(raw)
            else:
                data = base64.b64decode(raw + "=" * (-len(raw) % 4))
        if cmd == "aes":
            out = aes_run(data, bytes.fromhex(key_hex), mode,
                           bytes.fromhex(iv_hex) if iv_hex else None, enc)
        else:
            out = rc4(data, key_hex.encode())
        if enc:
            print(out.hex())          # 加密统一吐 hex，方便管道接力
        else:
            try:
                print(out.decode("utf-8"))
            except Exception:
                sys.stdout.buffer.write(out)
                print()
        return 0

    if cmd == "rsa":
        if not n_opt or not e_opt:
            die("需要 --n 和 --e")
        if d_opt and c_opt is not None:
            m = pow(c_opt, d_opt, n_opt)
            print("明文 = %r" % int_to_bytes(m))
            return 0
        w = rsa_wiener(n_opt, e_opt)
        if w:
            d, p, q = w
            print("Wiener 攻击成功：d=%d p=%d q=%d" % (d, p, q))
            if c_opt is not None:
                print("明文 = %r" % int_to_bytes(pow(c_opt, d, n_opt)))
            return 0
        for line in rsa_attack(n_opt, e_opt, c_opt):
            print(line)
        return 0

    if cmd == "jwt":
        if not rest:
            die("缺少 token")
        hdr, pay, parts = jwt_parse(rest[0])
        print("header :", json.dumps(hdr, ensure_ascii=False))
        print("payload:", json.dumps(pay, ensure_ascii=False, indent=1))
        if "--crack" in argv:
            w = jwt_crack(rest[0], wordlist)
            print("HS256 密钥:", w if w else "没爆破出来")
        return 0

    die("未知子命令：%s" % cmd)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("出错：%s" % e)
        sys.exit(1)
