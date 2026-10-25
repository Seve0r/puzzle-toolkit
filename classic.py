#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
古典密码工具箱。纯标准库。

子命令（都能 `-h` 看细节）：
  caesar      [--key N] <text>    凯撒；不给 key 就 26 个全爆破并按英文契合度排序
  vigenere    --key KEY <text>    维吉尼亚，加/解密用 --enc
  vigcrack    <text>              维吉尼亚无密钥自动破解（IC 定长 + 逐列频率）
  affine      [--a N --b N] <text> 仿射；不给参数就 312 种全爆破
  sub         <text>              单表替换自动破解（爬山法）
  bacon       [--old] <text>      培根密码（A/B 或 0/1，也吃大小写隐写）
  railfence   [--rails N] <text>  栅栏；不给栏数就全爆破
  columnar    [--key KEY] <text>  列置换；不给 key 就按长度爆破
  atbash      <text>              Atbash（反字母表）
  a1z26       [--dec] <text>      A1Z26（1-26 ↔ a-z）
  polybius    [--dec] <text>      波利比奥斯方阵（I/J 合并）
  playfair    --key KEY <text>    普莱菲尔方阵，--enc 加密，--clean 去掉填充 x
  adfgx       --key KEY [--trans KEY] <text>
  keyboard    [--layout qwerty|dvorak|azerty] <text>  键盘错位还原
  t9          <digits>            手机九宫格，列出所有可能
  auto        <text>              全部跑一遍，按英文契合度列出

通用：
  --enc            编码方向（默认解码）
  -q/--quiet       只输出结果
  -f/--file FILE   从文件读输入（长密文/多行必备，路径支持 ~）
  -n N             只显示前 N 个候选（默认 10）
"""
import sys
import os
import re
import math
import itertools
import json

EN_FREQ = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
           0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
           6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]

COMMON_WORDS = set(
    "the be to of and in that have it for not on with he as you do at this but "
    "his by from they we say her she or an will my one all would there their "
    "what so up out if about who get which go me when make can like time no "
    "just him know take people into year your good some could them see other "
    "than then now look only come its over think also back after use two how "
    "our work first well way even new want because any these give day most us".split())

BIGRAMS = {
    "th": 3.9, "he": 3.2, "in": 2.6, "er": 2.4, "an": 2.3, "re": 2.2,
    "on": 2.1, "at": 2.0, "en": 1.9, "nd": 1.8, "ti": 1.7, "es": 1.7,
    "or": 1.6, "te": 1.6, "of": 1.5, "ed": 1.5, "is": 1.5, "it": 1.4,
    "al": 1.4, "ar": 1.3, "st": 1.3, "to": 1.3, "nt": 1.2, "ng": 1.2,
    "se": 1.1, "ha": 1.1, "as": 1.0, "ou": 1.0, "io": 0.9, "le": 0.9,
    "ve": 0.9, "co": 0.8, "me": 0.8, "de": 0.8, "hi": 0.7, "ri": 0.7,
    "ro": 0.7, "ic": 0.7, "ne": 0.7, "ea": 0.6, "ra": 0.6, "ce": 0.6,
    "li": 0.6, "ch": 0.6, "ll": 0.6, "be": 0.6, "ma": 0.5, "si": 0.5,
    "om": 0.5, "ur": 0.5,
}

ALPHA = "abcdefghijklmnopqrstuvwxyz"


# ------------------------------------------------------------------ 基础

def only_letters(s):
    return "".join(c for c in s.lower() if c.isalpha())


def chi_squared(letters):
    n = len(letters)
    if n == 0:
        return 1e9
    obs = [0] * 26
    for c in letters:
        obs[ord(c) - 97] += 1
    chi = 0.0
    for i in range(26):
        exp = EN_FREQ[i] * n / 100.0
        if exp <= 0:
            continue
        chi += (obs[i] - exp) ** 2 / exp
    return chi


def english_score(s):
    """越大越像英文。

    权重经实测校准，两个坑都踩过：

    ① bigram 不能累加主导。早期让 bigram 求和乘 4，结果"部分正确 + 部分乱码"的文本
       反而比完美明文得分高（乱码凑出的 th/he/en/an 会把分数顶上去），破解器选假密钥。
       现在 bigram 一律**除以长度归一化**。
    ② chi² 在短文本上不可靠。十几个字母时频率统计纯属噪声，会压过真正有意义的
       bigram/单词信号（实测 "Wkh txlfn eurzq ira" 的正确答案只赢 0.8 分）。
       所以按样本量自适应：字少时降 chi² 权重、升 bigram 权重，字多时反过来。
    """
    letters = only_letters(s)
    if len(letters) < 2:
        return -1e6

    n = len(letters)
    # 样本量置信度：30 字母以下 chi² 完全不参与。
    # 16 个字母的英文天然"每个字母各出现一次"，chi² 会判它极不像英文，
    # 反而把均匀分布的乱码判成好文本——极短文本必须只看 bigram。
    conf = min(1.0, max(0.0, (n - 30) / 60.0))
    chi_w = 1.2 * conf                  # 30 字母 0 → 90 字母 1.2
    big_w = 55.0 - 25.0 * conf          # 30 字母 55 → 90 字母 30

    sc = -chi_squared(letters) * chi_w

    low = s.lower()
    bl = len(low) - 1
    if bl > 0:
        big = 0.0
        for i in range(bl):
            big += BIGRAMS.get(low[i:i + 2], 0.0) ** 1.5
        sc += (big / bl) * big_w

    words = re.findall(r"[a-z]{2,}", low)
    if words:
        hits = sum(1 for w in words if w in COMMON_WORDS)
        sc += 25.0 * hits
        sc += 8.0 * hits / len(words)

    # 长单词奖励（真实英文单词普遍较长）
    for w in words:
        if len(w) >= 5:
            sc += 2.0
    # 单字母词只允许 a / i
    for w in words:
        if len(w) == 1 and w not in ("a", "i"):
            sc -= 6.0
    return sc


# ---------------------------------------------------------------- 词表打分
# 用"能切成多少个真单词"做覆盖率评分，这是破解单表替换最有效的信号——
# bigram 只能看出"像不像英语"，词表能直接看出"这段文字到底是不是英语"。
#
# 词表来源按顺序取第一个能用的：
#   1. 环境变量 PUZZLE_WORDLIST 指定的文件
#   2. 脚本旁边的 data/words.txt（随仓库分发，各平台结果一致）
#   3. 常见系统词典（Linux 各发行版 / macOS）
# 自带的 data/words.txt 是精选高频词，比系统词典干净：系统词典里
# aa / ab / zz 这类垃圾条目会让乱码也切出"真词"，覆盖率虚高。
# Windows 上没有 /usr/share/dict，所以靠第 2 条。
_HERE = os.path.dirname(os.path.abspath(__file__))
_WORDLIST_CANDIDATES = [
    os.environ.get("PUZZLE_WORDLIST", ""),
    os.path.join(_HERE, "data", "words.txt"),
    os.path.join(_HERE, "..", "data", "words.txt"),
    "/usr/share/dict/words",
    "/usr/share/dict/american-english",
    "/usr/share/dict/british-english",
    "/usr/local/share/dict/words",
]


def _load_wordlist():
    for _path in _WORDLIST_CANDIDATES:
        if not _path:
            continue
        try:
            _found = set()
            with open(_path, encoding="utf-8", errors="ignore") as _f:
                for _line in _f:
                    _w = _line.strip().lower()
                    if 2 <= len(_w) <= 9 and _w.isalpha():
                        _found.add(_w)
        except Exception:
            continue
        if _found:
            return _found, os.path.normpath(_path)
    return set(), None


WORDS, _WORDLIST_USED = _load_wordlist()

MAX_WORD_LEN = 9
_NO_WORDLIST_WARNED = False


def word_coverage(s):
    """返回能被切分成词表单词的字母占比（0~1）。用 DP 求最大覆盖。"""
    global _NO_WORDLIST_WARNED
    if not WORDS:
        # 静默降级最坑：用户会以为在用词表打分，其实那一项恒为 0。
        if not _NO_WORDLIST_WARNED:
            _NO_WORDLIST_WARNED = True
            sys.stderr.write(
                "[提示] 没找到英语词表，评分退化为纯 bigram，候选排序可能不准。\n"
                "      修：把 words.txt 放到本脚本同级的 data/ 目录，"
                "或用环境变量 PUZZLE_WORDLIST 指定路径。\n")
        return 0.0
    n = len(s)
    if n < 4:
        return 0.0
    # 只认 3 字母以上的词：in / at / do 这种双字母词在乱码里到处都能凑出来，
    # 会让乱码覆盖率虚高到 0.9，区分度就没了。长词额外加权。
    best = [0.0] * (n + 1)
    for i in range(1, n + 1):
        prev = best[i - 1]
        for L in range(3, min(MAX_WORD_LEN, i) + 1):
            if s[i - L:i] in WORDS:
                v = best[i - L] + L * (1.0 + 0.25 * (L - 3))
                if v > prev:
                    prev = v
        best[i] = prev
    return best[n] / float(n)


def nonletters_ok(s):
    """保留原文的大小写与标点结构，用于展示"""
    return s


def shift_alpha(s, k):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def clean_key(key):
    return only_letters(key)


def modinv(a, m=26):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("%d 在 mod 26 下没有逆元（必须与 26 互素）" % a)


# ------------------------------------------------------------------ 凯撒

def caesar_dec(s, k):
    return shift_alpha(s, -k)


def caesar(text, key=None, top=26):
    if key is not None:
        try:
            key = int(key)
        except (TypeError, ValueError):
            raise ValueError("--key 必须是整数，收到: %r" % (key,))
        return [(key, caesar_dec(text, key))]
    res = [(k, caesar_dec(text, k)) for k in range(26)]
    res.sort(key=lambda kv: -english_score(kv[1]))
    return res[:top]


# ------------------------------------------------------------------ 维吉尼亚

def vig_shift(s, key, enc=False):
    k = clean_key(key)
    if not k:
        raise ValueError("密钥不能为空")
    out = []
    i = 0
    for c in s:
        if c.isalpha():
            base = 97 if c.islower() else 65
            kk = ord(k[i % len(k)]) - 97
            if enc:
                out.append(chr((ord(c) - base + kk) % 26 + base))
            else:
                out.append(chr((ord(c) - base - kk) % 26 + base))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def index_of_coincidence(letters):
    n = len(letters)
    if n < 2:
        return 0.0
    freq = [0] * 26
    for c in letters:
        freq[ord(c) - 97] += 1
    return sum(f * (f - 1) for f in freq) / float(n * (n - 1))


LOGFREQ = {ALPHA[i]: math.log(EN_FREQ[i] / 100.0) for i in range(26)}


def _best_caesar(col):
    """单列求最可能的凯撒偏移。用对数似然而不是 chi²——列里只有二十来个字母，
    chi² 的期望值太小、噪声大；对数似然对短样本稳得多。"""
    best_k, best_s = 0, -1e18
    for k in range(26):
        s = 0.0
        for c in shift_alpha(col, -k):
            s += LOGFREQ[c]
        if s > best_s:
            best_s, best_k = s, k
    return best_k, best_s


def _refine_key(text, key, rounds=2):
    """逐列频率分析偶尔会错一两个字母（那一列碰巧缺高频字）。
    这里用整段明文的契合度做坐标下降，把密钥微调到最优。"""
    k = list(key)
    best_txt = vig_shift(text, "".join(k), enc=False)
    best = english_score(best_txt)
    for _ in range(rounds):
        improved = False
        for i in range(len(k)):
            old = k[i]
            for cand in ALPHA:
                if cand == old:
                    continue
                k[i] = cand
                txt = vig_shift(text, "".join(k), enc=False)
                sc = english_score(txt)
                if sc > best + 1e-9:
                    best, best_txt, improved = sc, txt, True
                    old = cand
                else:
                    k[i] = old
            k[i] = old
        if not improved:
            break
    return "".join(k), best_txt, best


LEN_PENALTY = 2.5


def _minimal_period(k):
    """secretsecret -> secret。去重时只保留最短周期。"""
    n = len(k)
    for p in range(1, n + 1):
        if n % p == 0 and k == k[:p] * (n // p):
            return k[:p]
    return k


def vigcrack(text, maxlen=20, top=5):
    """无密钥破解。

    刻意不用 IC 判密钥长度：IC 对密钥的**倍数**特别敏感（密钥 6 位时，12 位同样高，
    甚至更高），按 IC 排序经常选出 12、18 这种假长度。
    这里改成：2..maxlen 每个长度都完整解一遍，用整段明文的英文契合度排名，
    再对前几名做密钥微调，最后用"最小周期"把 secretsecret 收敛成 secret。
    """
    letters = only_letters(text)
    if len(letters) < 20:
        raise ValueError("文本太短，维吉尼亚破解至少需要 20 个字母（现在 %d）" % len(letters))
    base_ic = index_of_coincidence(letters)

    upper = min(maxlen, max(2, len(letters) // 3))
    rough = []
    for kl in range(2, upper + 1):
        key = "".join(ALPHA[_best_caesar(letters[i::kl])[0]] for i in range(kl))
        plain = vig_shift(text, key, enc=False)
        # 长密钥自由度大、更容易刷高契合度（过拟合），必须按长度扣分
        rough.append((english_score(plain) - LEN_PENALTY * kl, key, plain))
    rough.sort(key=lambda x: -x[0])

    # 每个密钥长度只留最好的一个，避免 12 位变体把 6 位挤掉
    picked, seen_len = [], set()
    for sc, key, plain in rough:
        if len(key) in seen_len:
            continue
        seen_len.add(len(key))
        picked.append((sc, key))
        if len(picked) >= 5:
            break

    results, seen_sig = [], set()
    for _, key in picked:
        k2, _, _ = _refine_key(text, key)
        k2 = _minimal_period(k2)
        plain = vig_shift(text, k2, enc=False)
        sig = only_letters(plain)[:60]
        if sig in seen_sig:
            continue
        seen_sig.add(sig)
        results.append((english_score(plain) - LEN_PENALTY * len(k2), k2, plain))
    results.sort(key=lambda x: -x[0])
    return results[:top], base_ic


# ------------------------------------------------------------------ 仿射

AFFINE_A = [a for a in range(1, 26) if math.gcd(a, 26) == 1]


def affine_dec(s, a, b):
    inv = modinv(a)
    out = []
    for c in s:
        if c.isalpha():
            base = 97 if c.islower() else 65
            x = ord(c) - base
            out.append(chr((inv * (x - b)) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def affine_enc(s, a, b):
    out = []
    for c in s:
        if c.isalpha():
            base = 97 if c.islower() else 65
            x = ord(c) - base
            out.append(chr((a * x + b) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def affine(text, a=None, b=None, top=10):
    if a is not None and b is not None:
        return [(a, b, affine_dec(text, a, b))], None
    res = []
    for aa in AFFINE_A:
        for bb in range(26):
            res.append((aa, bb, affine_dec(text, aa, bb)))
    res.sort(key=lambda x: -english_score(x[2]))
    return res[:top], True


# ------------------------------------------------------------------ 单表替换（爬山）

def sub_hillclimb(text, restarts=12, iterations=4000):
    """在 26! 空间里爬山，随机重启若干次取最优。返回几个不同结果。"""
    import random
    letters = only_letters(text)
    if len(letters) < 20:
        raise ValueError("文本太短（至少 20 个字母），单表替换破解不可靠")

    def apply(mapping):
        return "".join(mapping.get(c, c) for c in text.lower())

    def eval_map(mapping):
        txt = apply(mapping)
        letters_txt = only_letters(txt)
        # 词表信号在短文本上会反向误导（错误映射也能切出一堆假词），
        # 随文本长度逐步加大权重，250 字母以上才给满。
        w = 500.0 * min(1.0, len(letters_txt) / 250.0)
        return english_score(txt) + word_coverage(letters_txt) * w

    # 起点一：按字母频率从高到低对齐英文字母频率（etaoin...）。
    # 纯随机起点在 200 字母以下的文本上很容易卡在局部最优。
    from collections import Counter
    freq_order = [c for c, _ in Counter(letters).most_common()]
    en_order = "etaoinshrdlucmfwypvbgkjqxz"
    seed_map = {}
    for c, plain in zip(freq_order, en_order):
        seed_map[c] = plain
    for c in ALPHA:
        seed_map.setdefault(c, c)

    starts = [dict(seed_map)]
    for _ in range(restarts):
        perm = list(ALPHA)
        random.shuffle(perm)
        starts.append(dict(zip(ALPHA, perm)))

    found = []
    for mapping0 in starts:
        mapping = dict(mapping0)
        cur = eval_map(mapping)
        for _ in range(iterations):
            i, j = random.sample(range(26), 2)
            mapping[ALPHA[i]], mapping[ALPHA[j]] = mapping[ALPHA[j]], mapping[ALPHA[i]]
            sc = eval_map(mapping)
            if sc >= cur:
                cur = sc
            else:
                mapping[ALPHA[i]], mapping[ALPHA[j]] = mapping[ALPHA[j]], mapping[ALPHA[i]]
        found.append((cur, dict(mapping)))
        if word_coverage(only_letters(apply(mapping))) > 0.95:
            break                      # 已经能切成通顺英文，提前收敛
    found.sort(key=lambda x: -x[0])
    out = []
    seen = set()
    for sc, m in found:
        txt = apply(m)
        if txt[:60] in seen:
            continue
        seen.add(txt[:60])
        keymap = "".join(k + "→" + v for k, v in sorted(m.items()))
        out.append((sc, keymap, txt))
    return out[:5]


# ------------------------------------------------------------------ 培根

BACON_26 = {}
for i in range(26):
    bits = format(i, "05b").replace("0", "A").replace("1", "B")
    BACON_26[bits] = ALPHA[i]

BACON_24 = {
    "AAAAA": "a", "AAAAB": "b", "AAABA": "c", "AAABB": "d", "AABAA": "e",
    "AABAB": "f", "AABBA": "g", "AABBB": "h", "ABAAA": "i", "ABAAB": "k",
    "ABABA": "l", "ABABB": "m", "ABBAA": "n", "ABBAB": "o", "ABBBA": "p",
    "ABBBB": "q", "BAAAA": "r", "BAAAB": "s", "BAABA": "t", "BAABB": "u",
    "BABAA": "w", "BABAB": "x", "BABBA": "y", "BABBB": "z",
}


def bacon_decode(text, old=False):
    """两种输入：显式 A/B 串，或藏在大写/小写里的隐写文本"""
    letters = "".join(c for c in text.upper() if c in "AB")
    # 如果 A/B 太少，试试大小写隐写：大写=B，小写=A
    if len(letters) < 5:
        bits = "".join("B" if c.isupper() else "A" for c in text if c.isalpha())
    else:
        bits = letters
    table = BACON_24 if old else BACON_26
    out = []
    for i in range(0, len(bits) - 4, 5):
        chunk = bits[i:i + 5]
        out.append(table.get(chunk, "?"))
    return "".join(out)


def bacon_encode(text, old=False):
    rev = {v: k for k, v in (BACON_24 if old else BACON_26).items()}
    return " ".join(rev.get(c.lower(), "?") for c in text if c.isalpha())


# ------------------------------------------------------------------ 栅栏

def rail_dec(s, rails):
    n = len(s)
    if rails <= 1 or rails >= n:
        return s
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    idx = [pattern[i % len(pattern)] for i in range(n)]
    counts = [idx.count(r) for r in range(rails)]
    pos = [sum(counts[:r]) for r in range(rails)]
    out = [None] * n
    for i, r in enumerate(idx):
        out[i] = s[pos[r]]
        pos[r] += 1
    return "".join(out)


def rail_enc(s, rails):
    if rails <= 1:
        return s
    rows = [[] for _ in range(rails)]
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    for i, c in enumerate(s):
        rows[pattern[i % len(pattern)]].append(c)
    return "".join("".join(r) for r in rows)


def railfence(text, rails=None, top=10):
    if rails is not None:
        return [(rails, rail_dec(text, rails))]
    res = [(r, rail_dec(text, r)) for r in range(2, min(len(text), 21))]
    res.sort(key=lambda x: -english_score(x[1]))
    return res[:top]


# ------------------------------------------------------------------ 列置换

def columnar_dec(s, key):
    """按列读取、按行写回的经典列置换。短列永远出现在末尾几列（行末不满）。"""
    k = clean_key(key)
    ncol = len(k)
    n = len(s)
    nrow = (n + ncol - 1) // ncol
    full = n - (nrow - 1) * ncol            # 最后一行实际占了几列
    col_len = [nrow if c < full else nrow - 1 for c in range(ncol)]
    order = sorted(range(ncol), key=lambda i: k[i])

    cols = {}
    pos = 0
    for c in order:
        cols[c] = s[pos:pos + col_len[c]]
        pos += col_len[c]

    out = []
    for r in range(nrow):
        for c in range(ncol):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)


def columnar_enc(s, key):
    k = clean_key(key)
    ncol = len(k)
    order = sorted(range(ncol), key=lambda i: k[i])
    nrow = (len(s) + ncol - 1) // ncol
    rows = [s[i * ncol:(i + 1) * ncol] for i in range(nrow)]
    cols = ["".join(r[c] for r in rows if c < len(r)) for c in range(ncol)]
    return "".join(cols[c] for c in order)


def columnar_brute(text, maxlen=10, top=8):
    """没有 key 时按可能长度全排列爆破（长度 > 7 时只抽样）"""
    results = []
    for klen in range(2, maxlen + 1):
        if klen <= 6:
            perms = itertools.permutations(ALPHA[:klen])
            sample = list(perms)
        else:
            import random
            sample = [tuple(random.sample(ALPHA[:klen], klen)) for _ in range(4000)]
        for perm in sample:
            key = "".join(perm)
            try:
                dec = columnar_dec(text, key)
            except Exception:
                continue
            results.append((english_score(dec), key, dec))
    results.sort(key=lambda x: -x[0])
    seen, out = set(), []
    for sc, key, dec in results:
        if dec[:50] in seen:
            continue
        seen.add(dec[:50])
        out.append((sc, key, dec))
        if len(out) >= top:
            break
    return out


# ------------------------------------------------------------------ Atbash / A1Z26

def atbash(s):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr(122 - (ord(c) - 97)))
        elif "A" <= c <= "Z":
            out.append(chr(90 - (ord(c) - 65)))
        else:
            out.append(c)
    return "".join(out)


def a1z26_decode(s):
    # 有明确分隔符时，每个数就是一个字母，绝不能合并——
    # 否则 "1 12 3" 会被贪心拼成 1*10+12=22 → 'v'，解成 "vc" 而不是 "alc"。
    if re.search(r"[\s,;:./|-]", s.strip()):
        nums = [int(x) for x in re.findall(r"\d+", s)]
        if not nums:
            raise ValueError("没有数字")
        return "".join(chr(n + 96) if 1 <= n <= 26 else "?" for n in nums)

    # 连续数字串：切分本身有歧义（"1123" 可以是 1-1-2-3 / 11-2-3 / 11-23 / 1-12-3），
    # 枚举所有合法切分，按英文契合度选最好的那个。
    digits = re.sub(r"\D", "", s)
    if not digits:
        raise ValueError("没有数字")

    if len(digits) > 25:
        # 切分数量按斐波那契增长，太长就退回贪心，避免卡死
        nums = [int(c) for c in digits]
        out, i = [], 0
        while i < len(nums):
            if i + 1 < len(nums) and 10 <= nums[i] * 10 + nums[i + 1] <= 26:
                out.append(chr(nums[i] * 10 + nums[i + 1] + 96))
                i += 2
            else:
                if 1 <= nums[i] <= 26:
                    out.append(chr(nums[i] + 96))
                i += 1
        return "".join(out)

    results = []

    def rec(i, acc):
        if i == len(digits):
            results.append("".join(acc))
            return
        for width in (1, 2):
            if i + width > len(digits):
                continue
            if width == 2 and digits[i] == "0":
                continue
            v = int(digits[i:i + width])
            if 1 <= v <= 26:
                acc.append(chr(v + 96))
                rec(i + width, acc)
                acc.pop()

    rec(0, [])
    if not results:
        raise ValueError("无法按 A1Z26 切分")
    results.sort(key=lambda x: -english_score(x))
    return results[0]


def a1z26_encode(s):
    return " ".join(str(ord(c) - 96) for c in s.lower() if "a" <= c <= "z")


# ------------------------------------------------------------------ 波利比奥斯

POLYBIUS_GRID = {}
_letters = "abcdefghiklmnopqrstuvwxyz"  # 去掉 j
for _i, _ch in enumerate(_letters):
    POLYBIUS_GRID["%d%d" % (_i // 5 + 1, _i % 5 + 1)] = _ch
POLYBIUS_REV = {v: k for k, v in POLYBIUS_GRID.items()}


def polybius_decode(s, merge_ij=True):
    digits = re.sub(r"\D", "", s)
    if len(digits) % 2:
        raise ValueError("数字个数必须是偶数")
    out = []
    for i in range(0, len(digits), 2):
        pair = digits[i:i + 2]
        out.append(POLYBIUS_GRID.get(pair, "?"))
    return "".join(out)


def polybius_encode(s):
    out = []
    for c in s.lower():
        if c == "j":
            c = "i"
        out.append(POLYBIUS_REV.get(c, "??"))
    return " ".join(out)


# ------------------------------------------------------------------ 普莱菲尔

def playfair_square(key):
    k = clean_key(key).replace("j", "i")
    seen = []
    for c in k:
        if c not in seen:
            seen.append(c)
    for c in "abcdefghiklmnopqrstuvwxyz":
        if c not in seen:
            seen.append(c)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


def _pf_pos(sq, ch):
    for r in range(5):
        for c in range(5):
            if sq[r][c] == ch:
                return r, c
    return None


def _pf_strip_pad(s):
    """去掉 Playfair 的填充 x：末尾补的那个，以及"lxl"这种为拆重复字母插入的。

    有极小概率误删原文里真实存在的 axa（如 taxa），所以留了 --keep-pad 开关。
    """
    if s.endswith("x"):
        s = s[:-1]
    changed = True
    while changed:
        changed = False
        for i in range(1, len(s) - 1):
            if s[i] == "x" and s[i - 1] == s[i + 1]:
                s = s[:i] + s[i + 1:]
                changed = True
                break
    return s


def playfair(s, key, enc=False, clean_pad=False):
    sq = playfair_square(key)
    txt = [c for c in s.lower() if c.isalpha()]
    txt = [("i" if c == "j" else c) for c in txt]

    pairs = []
    if enc:
        # 分组：相邻字母相同时中间插 x 拆开；奇数长度末尾补 x
        i = 0
        while i < len(txt):
            a = txt[i]
            if i + 1 >= len(txt):
                pairs.append((a, "x"))
                i += 1
            elif txt[i + 1] == a:
                pairs.append((a, "x"))
                i += 1
            else:
                pairs.append((a, txt[i + 1]))
                i += 2
    else:
        # 密文必然成对出现，奇数长度说明输入有问题，不能静默补位
        if len(txt) % 2:
            raise ValueError(
                "密文长度必须是偶数，现在是 %d 个字母——可能少打或多打了字符" % len(txt))
        pairs = [(txt[i], txt[i + 1]) for i in range(0, len(txt), 2)]

    out = []
    d = 1 if enc else -1
    for a, b in pairs:
        posA, posB = _pf_pos(sq, a), _pf_pos(sq, b)
        if posA is None or posB is None:
            raise ValueError("字母不在方阵里：%r" % (a if posA is None else b))
        ra, ca = posA
        rb, cb = posB
        if ra == rb:
            out.append(sq[ra][(ca + d) % 5])
            out.append(sq[rb][(cb + d) % 5])
        elif ca == cb:
            out.append(sq[(ra + d) % 5][ca])
            out.append(sq[(rb + d) % 5][cb])
        else:
            out.append(sq[ra][cb])
            out.append(sq[rb][ca])
    res = "".join(out)
    if not enc and clean_pad:
        res = _pf_strip_pad(res)
    return res


# ------------------------------------------------------------------ ADFGX

def adfgx_square(key):
    k = clean_key(key).replace("j", "i")
    seen = []
    for c in k:
        if c not in seen:
            seen.append(c)
    for c in "abcdefghiklmnopqrstuvwxyz":
        if c not in seen:
            seen.append(c)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


ADFGX_ROWS = "ADFGX"
ADFGX_COLS = "ADFGX"


def adfgx_dec(s, key, trans_key=None):
    sq = adfgx_square(key)
    letters = "".join(c for c in s.upper() if c in ADFGX_ROWS)
    if trans_key:
        letters = columnar_dec(letters, trans_key)
    out = []
    for i in range(0, len(letters) - 1, 2):
        r = ADFGX_ROWS.index(letters[i])
        c = ADFGX_COLS.index(letters[i + 1])
        out.append(sq[r][c])
    return "".join(out)


# ------------------------------------------------------------------ 键盘错位

LAYOUTS = {
    "qwerty": "qwertyuiopasdfghjklzxcvbnm",
    "dvorak": "pyfgcrlaoeuidhtnsqjkxbmwvz",
    "azerty": "azertyuiopqsdfghjklmwxcvbn",
}


def keyboard(text, layout="qwerty", shift=-1):
    """把文字按某布局左右平移 shift 位还原（常见于"手放错一格"）"""
    base = LAYOUTS.get(layout)
    if not base:
        raise ValueError("不认识的布局：%s" % layout)
    out = []
    for c in text:
        low = c.lower()
        if low in base:
            i = (base.index(low) + shift) % len(base)
            nc = base[i]
            out.append(nc.upper() if c.isupper() else nc)
        else:
            out.append(c)
    return "".join(out)


def keyboard_all(text):
    res = []
    for name in LAYOUTS:
        for sh in (-1, 1, -2, 2):
            res.append(("%s%+d" % (name, sh), keyboard(text, name, sh)))
    res.sort(key=lambda kv: -english_score(kv[1]))
    return res


# ------------------------------------------------------------------ T9 九宫格

T9 = {
    "2": "abc", "3": "def", "4": "ghi", "5": "jkl", "6": "mno",
    "7": "pqrs", "8": "tuv", "9": "wxyz",
}


def t9(text, limit=200):
    groups = []
    for c in text:
        if c in T9:
            groups.append(T9[c])
        elif c.isdigit():
            groups.append(c)
        elif c in " 0":
            groups.append(" ")
    if not groups:
        return []
    combos = []
    total = 1
    for g in groups:
        total *= max(1, len(g))
    if total > limit:
        # 太多了，只给每一位的可选字母
        return [("%s → %s" % (c, T9.get(c, c)),) for c in text]
    for prod in itertools.product(*groups):
        combos.append("".join(prod))
    combos.sort(key=lambda s: -english_score(s))
    return [(s,) for s in combos]


# ------------------------------------------------------------------ auto

def auto(text, top=10):
    """所有手法跑一遍，按英文契合度汇总"""
    pool = [(english_score(text), "(原样)", text)]  # 输入本来可读时必须能原样返回

    for k, out in caesar(text):
        pool.append((english_score(out), "caesar(k=%d)" % k, out))
    pool.append((english_score(atbash(text)), "atbash", atbash(text)))
    pool.append((english_score(rail_dec(text, 3)), "railfence(3)", rail_dec(text, 3)))

    for rails, out in railfence(text, top=6):
        pool.append((english_score(out), "railfence(%d)" % rails, out))
    for a, b, out in affine_enc_free(text, top=5):
        pool.append((english_score(out), "affine(a=%d,b=%d)" % (a, b), out))
    for name, out in keyboard_all(text)[:4]:
        pool.append((english_score(out), "keyboard(%s)" % name, out))

    if re.fullmatch(r"[\d\s]+", text.strip()):
        try:
            out = a1z26_decode(text)
            pool.append((english_score(out), "a1z26", out))
        except Exception:
            pass
        try:
            out = polybius_decode(text)
            pool.append((english_score(out), "polybius", out))
        except Exception:
            pass
    if re.fullmatch(r"[abAB\s]+", text.strip()):
        try:
            out = bacon_decode(text)
            pool.append((english_score(out), "bacon", out))
        except Exception:
            pass

    # "原样"给一点先验：文本本来就通顺时，最省事的解释就是不折腾。
    # 不加这个先验的话，railfence 之类会把词打乱重排，偶尔凑出更高 bigram 分数而胜出。
    pool.sort(key=lambda x: -(x[0] + (12.0 if x[1] == "(原样)" else 0.0)))
    seen, out = set(), []
    for sc, name, res in pool:
        if res[:50] in seen:
            continue
        seen.add(res[:50])
        out.append((sc, name, res))
    return out[:top]


def affine_enc_free(text, top=5):
    res, _ = affine(text, top=top)
    return res


# ------------------------------------------------------------------ CLI

def show_list(rows, fmt, limit=None, quiet=False):
    if limit:
        rows = rows[:limit]
    if quiet:
        for r in rows:
            print(r[-1])
        return
    for r in rows:
        print("  " + fmt(r))


def main():
    argv = sys.argv[1:]
    quiet = "-q" in argv or "--quiet" in argv
    argv = [a for a in argv if a not in ("-q", "--quiet")]
    clean_pad = "--clean" in argv
    argv = [a for a in argv if a != "--clean"]

    top = 10
    if "-n" in argv:
        i = argv.index("-n")
        top = int(argv[i + 1])
        argv = argv[:i] + argv[i + 1:]

    enc = "--enc" in argv or "-e" in argv
    argv = [a for a in argv if a not in ("--enc", "-e")]

    def opt(name, cast=str, default=None):
        nonlocal argv
        if name in argv:
            i = argv.index(name)
            v = cast(argv[i + 1])
            argv = argv[:i] + argv[i + 2:]   # 同时吃掉选项名和它的值
            return v
        return default

    key = opt("--key", str, None)
    a_opt = opt("--a", int, None)
    b_opt = opt("--b", int, None)
    rails = opt("--rails", int, None)
    layout = opt("--layout", str, "qwerty")
    trans_key = opt("--trans", str, None)
    old = "--old" in argv
    argv = [x for x in argv if x != "--old"]
    do_dec = "--dec" in argv
    argv = [x for x in argv if x != "--dec"]

    # -f / --file：从文件读输入。README 的「通用选项」表一直写着「适用全部」，
    # 但这里从来没实现过——`-f` 会被下面的 " ".join 当成密文的一部分静默吃掉，
    # 解出满屏垃圾却看不出原因，比直接报错更坑。
    # 内容作为一个整体参数追加到末尾，避免被空格拆散后再 join 重组出偏差。
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
    text = " ".join(argv[1:])
    if not text:
        print("缺少输入文本")
        return 2

    try:
        if cmd == "caesar":
            rows = caesar(text, key, top)
            if quiet:
                for k, out in rows:
                    print(out)
            else:
                print("凯撒爆破（按契合度）：")
                for k, out in rows[:top]:
                    print("  k=%-2d  %s" % (k, out))
            return 0

        if cmd == "vigenere":
            if not key:
                print("需要 --key")
                return 2
            print(vig_shift(text, key, enc=enc))
            return 0

        if cmd == "vigcrack":
            rows, ic = vigcrack(text, top=5)
            print("整体 IC = %.4f（英语约 0.0667，越低越可能多表）\n" % ic)
            for sc, k, out in rows:
                print("  密钥 %-12s 得分 %7.1f" % (k, sc))
                print("    %s" % out)
            return 0

        if cmd == "affine":
            rows, brute = affine(text, a_opt, b_opt, top)
            if quiet:
                for r in rows:
                    print(r[-1])
            elif brute:
                print("仿射爆破：")
                for a, b, out in rows:
                    print("  a=%-2d b=%-2d  %s" % (a, b, out))
            else:
                a, b, out = rows[0]
                print(out)
            return 0

        if cmd == "affine-enc":
            if a_opt is None or b_opt is None:
                print("需要 --a 和 --b")
                return 2
            print(affine_enc(text, a_opt, b_opt))
            return 0

        if cmd == "sub":
            rows = sub_hillclimb(text)
            for sc, keymap, out in rows:
                print("  得分 %7.1f" % sc)
                print("    映射 %s" % keymap)
                print("    明文 %s\n" % out)
            return 0

        if cmd == "bacon":
            print(bacon_decode(text, old))
            return 0

        if cmd == "railfence":
            if enc and rails:
                print(rail_enc(text, rails))
                return 0
            rows = railfence(text, rails, top)
            if quiet:
                for r, out in rows:
                    print(out)
            elif rails:
                print(rows[0][1])
            else:
                print("栅栏爆破：")
                for r, out in rows:
                    print("  %-2d 栏  %s" % (r, out))
            return 0

        if cmd == "columnar":
            if key:
                print(columnar_enc(text, key) if enc else columnar_dec(text, key))
                return 0
            rows = columnar_brute(text)
            for sc, k, out in rows:
                print("  key=%-10s 得分 %7.1f  %s" % (k, sc, out))
            return 0

        if cmd == "atbash":
            print(atbash(text))
            return 0

        if cmd == "a1z26":
            print(a1z26_encode(text) if enc else a1z26_decode(text))
            return 0

        if cmd == "polybius":
            print(polybius_encode(text) if enc else polybius_decode(text))
            return 0

        if cmd == "playfair":
            if not key:
                print("需要 --key")
                return 2
            print(playfair(text, key, enc=enc, clean_pad=clean_pad))
            return 0

        if cmd == "adfgx":
            if not key:
                print("需要 --key")
                return 2
            print(adfgx_dec(text, key, trans_key))
            return 0

        if cmd == "keyboard":
            if "-1" in argv or "--all" in argv:
                for name, out in keyboard_all(text):
                    print("  %-12s %s" % (name, out))
            else:
                print(keyboard(text, layout, -1))
            return 0

        if cmd == "t9":
            rows = t9(text, limit=500)
            for r in rows[:50]:
                print("  " + r[0])
            return 0

        if cmd == "auto":
            rows = auto(text, top)
            print("全部手法尝试（按英文契合度）：\n")
            for sc, name, out in rows:
                print("  %-22s %7.1f  %s" % (name, sc, out))
            return 0

        print("未知子命令：%s" % cmd)
        print(__doc__)
        return 2

    except Exception as e:
        print("出错：%s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
