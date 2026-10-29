#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进制转换（数值视角）。

只管「一个数怎么用别的进制写」，**不碰字节流编解码**——那是 codec.py 的活：
  num.py ff --from 16     → 255        （这里：一个数换种写法）
  codec.py dec hex 48656c6c6f → Hello  （那边：字节序列 ↔ 文本）

用法：
  num.py <数> [...]                列出 dec / hex / bin / oct 四种形式
  num.py <数> --to N               只输出指定进制
  num.py <数> --from N --to M      两端都指定

选项：
  --from N      输入进制 2..36。不给就猜：0x/0b/0o 按前缀，含 a-f 判 16，其余判 10
  --to N        输出进制 2..36。不给就列出四种形式
  -f, --file F  从文件读，每行一个数（行内用空格分隔的算多个）；F 给 - 表示 stdin
  --upper       hex / 36 进制用大写字母
  --prefix      输出带 0x / 0b / 0o 前缀（只对 2 / 8 / 16 有意义）
  --pad N       补零到 N 位（位数不含正负号和前缀）
  -q, --quiet   只输出结果，不往 stderr 写提示

例：
  num.py 255                      dec 255 / hex ff / bin 11111111 / oct 377
  num.py 255 --to 16              ff
  num.py ff --from 16             255
  num.py 0b1010                   10
  num.py 255 --to 16 --upper      FF
  num.py 255 --to 16 --prefix     0xff
  num.py 5 --to 2 --pad 8         00000101
  num.py 1 2 3 --to 2 --pad 8     三行，每行 8 位
  num.py -f nums.txt --to 16      批量
  cat nums.txt | num.py --to 16   管道

为什么要有 --pad：进制转换会吃掉前导零。0x00ff 和 0xff 是同一个数，但在
数据里是两种字节——bin(int("00000001",2)) 回来只剩 "1"，8 位变 1 位。
做字节级往返（点阵位流、定长字段）时必须补零。
"""

import sys


DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"
BASE_LABEL = [(10, "dec"), (16, "hex"), (2, "bin"), (8, "oct")]
PREFIX_OF = {2: "0b", 8: "0o", 16: "0x"}


def die(msg, code=1):
    sys.stderr.write(msg.rstrip("\n") + "\n")
    return code


def to_base(n, base, upper=False):
    """整数 -> 指定进制的字符串（2..36）。Python 的 int 只负责反向。"""
    if n == 0:
        return "0"
    neg = n < 0
    if neg:
        n = -n
    buf = []
    while n:
        n, r = divmod(n, base)
        buf.append(DIGITS[r])
    s = "".join(reversed(buf))
    return ("-" if neg else "") + (s.upper() if upper else s)


def fmt_num(n, base, upper=False, prefix=False, pad=None):
    body = to_base(n, base, upper)
    neg = body.startswith("-")
    if neg:
        body = body[1:]
    if pad:
        body = body.rjust(pad, "0")
    pre = PREFIX_OF.get(base, "") if prefix else ""
    return ("-" if neg else "") + pre + body


def parse_num(s, base=None):
    """解析一个数。返回 (值, 实际用的进制, 是否自动判定)。

    自动判定的规则刻意保守：进制猜错的代价比多敲一个 --from 高得多。
    """
    t = s.strip()
    if not t:
        raise ValueError("空")
    sign = 1
    if t[0] in "+-":
        if t[0] == "-":
            sign = -1
        t = t[1:]
    low = t.lower()
    auto = base is None
    if low.startswith("0x"):
        base, t = 16, t[2:]
    elif low.startswith("0b"):
        base, t = 2, t[2:]
    elif low.startswith("0o"):
        base, t = 8, t[2:]
    elif auto:
        base = 16 if any(c in "abcdef" for c in low) else 10
    if not t:
        raise ValueError("只有前缀没有数字")
    return sign * int(t, base), base, auto


def check_base(b, what):
    if b is None:
        return None
    if not (2 <= b <= 36):
        raise ValueError(
            "%s 进制必须是 2..36。再往上没有现成符号可用（0-9 + a-z 正好 36 个），"
            "需要自带字符集——那属于编码不是进制，用 codec.py 的 base58 / base62" % what)
    return b


def show_all(n, upper, prefix, pad, src_base):
    rows = ["%-4s  %s" % (label, fmt_num(n, b, upper, prefix, pad))
            for b, label in BASE_LABEL]
    # 输入用的进制不在这四个里（比如 36）就补一行，方便核对
    if src_base and src_base not in (2, 8, 10, 16):
        rows.append("%-4s  %s" % ("b%d" % src_base,
                                  fmt_num(n, src_base, upper, prefix, pad)))
    return "\n".join(rows)


def main():
    argv = sys.argv[1:]
    # `--` 之后一律当数值、不再当选项。负数本来就不和任何选项重名，
    # 这里只是给 `num.py -- -1` 这种写法留个明确出口。
    tail = []
    if "--" in argv:
        cut = argv.index("--")
        tail = argv[cut + 1:]
        argv = argv[:cut]
    quiet = "-q" in argv or "--quiet" in argv
    argv = [a for a in argv if a not in ("-q", "--quiet")]
    upper = "--upper" in argv
    argv = [a for a in argv if a != "--upper"]
    prefix = "--prefix" in argv
    argv = [a for a in argv if a != "--prefix"]

    def opt(name, cast=str, default=None):
        nonlocal argv
        if name in argv:
            i = argv.index(name)
            if i + 1 >= len(argv):
                return ("ERR", "%s 后面要跟一个值" % name)
            try:
                v = cast(argv[i + 1])
            except Exception:
                return ("ERR", "%s 的值 %r 不合法" % (name, argv[i + 1]))
            argv = argv[:i] + argv[i + 2:]
            return v
        return default

    if argv and argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0

    optvals = {}
    for name, cast in (("--from", int), ("--to", int), ("--pad", int),
                       ("-f", str), ("--file", str)):
        v = opt(name, cast, None)
        if isinstance(v, tuple) and v and v[0] == "ERR":
            return die(v[1], 2)
        optvals[name] = v

    try:
        base_from = check_base(optvals["--from"], "--from")
        base_to = check_base(optvals["--to"], "--to")
    except ValueError as e:
        return die(str(e), 2)
    pad = optvals["--pad"]
    if pad is not None and pad < 1:
        return die("--pad 至少是 1", 2)
    path = optvals["-f"] or optvals["--file"]

    # 收集待转换的数：位置参数 > -f 文件 > stdin
    items = list(argv) + tail
    if path:
        if items:
            return die("给了 -f 就不要再跟位置参数了", 2)
        try:
            if path == "-":
                items = sys.stdin.read().split()
            else:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    items = f.read().split()
        except OSError as e:
            return die("读不了 %s：%s" % (path, e))
    elif not items:
        if sys.stdin.isatty():
            print(__doc__)
            return 0
        items = sys.stdin.read().split()

    if not items:
        return die("没有输入", 2)

    out = []
    hinted = False
    for tok in items:
        try:
            n, used, auto = parse_num(tok, base_from)
        except ValueError as e:
            return die("解析不了 %r：%s" % (tok, e), 2)
        # 纯 0/1、长度是 8 的倍数、又没指定 --from：很可能是二进制串。
        # 不替用户改判定（进制猜错代价高），但得提一句，否则他自己想不到。
        body = tok.lstrip("+-").lower()
        if (not quiet and auto and used == 10 and not hinted and len(body) >= 8
                and len(body) % 8 == 0 and set(body) <= {"0", "1"}):
            sys.stderr.write(
                "提示：%s 看着像二进制串，要按二进制算请加 --from 2\n" % tok)
            hinted = True
        if base_to is None:
            out.append(show_all(n, upper, prefix, pad, used))
        else:
            out.append(fmt_num(n, base_to, upper, prefix, pad))

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
