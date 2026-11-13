#!/usr/bin/env python3
"""性能基准：回答「现在多慢 / 改完多快 / 结果还对不对」。

和 `tests/run.py` 的分工
    tests/run.py    断言「行为对不对」—— 输出逐字符相等，秒级跑完
    tools/bench.py  度量「跑得快不快」，同时校验「结果没变」，分钟级

用法
    python3 tools/bench.py                     # 全部跑一遍
    python3 tools/bench.py --list              # 列出基准项（含耗时量级）
    python3 tools/bench.py --only hillclimb    # 只跑名字里含 hillclimb 的
    python3 tools/bench.py --quick             # 缩小规模，开发迭代用
    python3 tools/bench.py --reps 7            # 每项重复次数（默认 5）
    python3 tools/bench.py --save base.json    # 存基线
    python3 tools/bench.py --compare base.json # 跟基线比

五条原则（缺一条，数字就不可信）
    1. **固定种子**：每次调用前 `random.seed()`。那几个爬山/爆破函数都吃全局
       random，不固定的话每次做的工作量都不同，快慢混在一起看不出因果关系。
    2. **重复取中位数**：偶发 GC 和调度会把平均值拖高，中位数扛得住。
    3. **记录结果摘要**：优化前后摘要必须一致。否则「变快」很可能是拿正确性
       换的——这是性能改动唯一真正危险的地方，也是本工具存在的理由。
    4. **报噪音水平**：小于噪音的变化不算改善，表格里直接标「无显著差异」。
    5. **记住是哪台机器测的**：基线里的毫秒数绑死在机器上。`--save` 会把 CPU
       型号 / 逻辑核数 / OS / Python 版本一起写进 `machine` 字段，`--compare`
       发现和当前机器不同时**只校验结果摘要、不判快慢**。没有这条，「换了台
       慢机器」和「代码退化了」在输出里长得一模一样，只能靠人记住当初在哪测
       的——靠不住。注意摘要本身是机器无关的，换机器时它仍然要照常校验。

本机噪音（2026-11-13 实测，32 核 Ryzen 9 8940HX，VSCode 开着）
    同一任务连跑 10 次：最小 1.826s / 中位 1.855s / 最大 1.879s，散布 2.9%，
    单次相对中位的偏差全在 ±1.6% 以内。所以 **>5% 的变化才值得当真**。
"""
import argparse
import atexit
import base64
import contextlib
import hashlib
import io
import json
import os
import platform
import random
import statistics
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import classic      # noqa: E402
import codec        # noqa: E402
import hashcrypto   # noqa: E402
import stego        # noqa: E402

# 本机计时噪音（百分比）。表格里用它判断「这个变化算不算数」。
#
# 实测：秒级的项散布约 2%，毫秒级的项（mojibake_cross / brute）能到 8~16%。
# 统一取 5%——比秒级项的实测噪音宽一点，避免毫秒级微基准天天误报；
# 代价是「优化 3%」这种结论不再被当真，那本来也不该当真。
NOISE = 5.0

LETTERS = "abcdefghijklmnopqrstuvwxyz"
_PLAIN = ("the quick brown fox jumps over the lazy dog and then runs away " * 60)


def _cipher(n, seed=1):
    """把英文原文按固定随机替换变成密文 —— 真实场景的输入，且确定可复现。"""
    rnd = random.Random(seed)
    perm = list(LETTERS)
    rnd.shuffle(perm)
    return _PLAIN[:n].translate(str.maketrans(LETTERS, "".join(perm)))


def _vig(n):
    """维吉尼亚密文（密钥 puzzle）。"""
    key = "puzzle"
    txt = "".join(c for c in _PLAIN if c.isalpha())[:n]
    return "".join(LETTERS[(LETTERS.index(c) + LETTERS.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(txt))


def _nested(layers=3):
    """base64 套 base64……让 codec.auto 真的往下剥，而不是一眼看穿。"""
    s = "puzzle toolkit benchmark payload " * 40
    for _ in range(layers):
        s = base64.b64encode(s.encode()).decode()
    return s


# ★ 输入要选得让被测函数**真的把活干完**。踩过：mojibake_cross 用
#   '缂栫爜娴嬭瘯' 时 6 个字的编码组合全部编不回去，直接空转返回，测出来
#   0.04ms —— 那不是「它很快」，是「它什么也没做」。换成真实案例
#   '僥僗僩梡偺暥帤楍'（能解出 8 条）并放大到 40 倍，才有意义。
_MOJI_CASE = "僥僗僩梡偺暥帤楍" * 40

# mojibake_split 走的是「含 U+FFFD 的分段还原」，输入必须带替换符才会进那段
# 代码（否则 _d_mojibake 一级就返回了，测的是别的路径）。同样放大到能解出
# 结果的长度——纯 '缂栫爜' 那种会返回 None，digest 全是 None 就失去意义了。
_MOJI_SPLIT_CASE = ("僥僗僩梡偺暥帤楍\ufffd" * 30).rstrip("\ufffd")

_GRID_FIXTURES = {}


def _grid_fixture(cols=64, cell=10):
    """生成一张白底黑块的点阵图，返回路径。第一次调用时生成，之后复用。

    用 `stego._png_encode_rgb`（它本来就是纯标准库的 PNG 编码器，qr 反色
    那里在用），所以仓库里不用存一张大图，也不需要谁去准备素材。

    实测识别率：48/64/96 格 × 8~12px，grid_read 报出来的 cols / rows / cell
    全部准确 —— 测的是真正的切格路径，不是早退。
    """
    key = (cols, cell)
    path = _GRID_FIXTURES.get(key)
    if path is not None:
        return path
    w = h = cols * cell
    rnd = random.Random(1)                 # 固定种子：图的 bit 布局每次相同
    bits = [rnd.randrange(2) for _ in range(cols * cols)]
    lines = []
    for cy in range(cols):
        row = bytearray(w)
        for cx in range(cols):
            v = 0 if bits[cy * cols + cx] else 255
            row[cx * cell:(cx + 1) * cell] = bytes([v]) * cell
        lines.append(bytes(row))
    full = b"".join(r for r in lines for _ in range(cell))
    png = stego._png_encode_rgb(w, h, full, full, full)
    fd, path = tempfile.mkstemp(suffix=".png", prefix="bench_grid_")
    with os.fdopen(fd, "wb") as f:
        f.write(png)
    _GRID_FIXTURES[key] = path
    atexit.register(lambda p=path: os.path.exists(p) and os.unlink(p))
    return path


# ---------------------------------------------------------------- 基准项
#
# run(quick) 里的 quick=True 是 --quick 模式：规模缩到约 1/8，用于改代码时
# 快速自查。**存基线必须用全量**，两种模式的数字不可比。

CASES = [
    {
        "name": "hillclimb/400",
        "note": "单表替换爬山（报告 15）——最重的一项",
        "seed": 7,
        "run": lambda q: classic.sub_hillclimb(
            _cipher(400), restarts=1 if q else 2, iterations=400 if q else 2000),
    },
    {
        "name": "hillclimb/800",
        "note": "同上，规模翻倍——看耗时是不是超线性",
        "seed": 7,
        "run": lambda q: classic.sub_hillclimb(
            _cipher(800), restarts=1, iterations=200 if q else 800),
    },
    {
        "name": "vigcrack/794",
        "note": "维吉尼亚自动破解（报告 16）",
        "seed": 0,
        "run": lambda q: classic.vigcrack(_vig(794), maxlen=10 if q else 20),
    },
    {
        "name": "a1z26/24",
        "note": "无分隔符切分枚举（报告 17）——指数增长：每 +4 位约 ×7",
        "seed": 0,
        "run": lambda q: classic.a1z26_decode("12" * (4 if q else 12)),
    },
    {
        "name": "mojibake_cross",
        "note": "源编码 × 目标编码双循环（报告 18），输入 ×40 才有量级",
        "seed": 0,
        "run": lambda q: codec.mojibake_cross(_MOJI_CASE[:len(_MOJI_CASE) // (4 if q else 1)]),
    },
    {
        "name": "mojibake/split",
        "note": "含 U+FFFD 的分段还原，同款 src×tgt 双循环；每段只该编码一次",
        "seed": 0,
        "run": lambda q: codec.mojibake_split(
            _MOJI_SPLIT_CASE[:len(_MOJI_SPLIT_CASE) // (4 if q else 1)]),
    },
    {
        "name": "codec/auto",
        "note": "递归剥皮 + 乱码兜底（报告 20），三层 base64 嵌套",
        "seed": 0,
        "run": lambda q: codec.auto(_nested(1 if q else 3)),
    },
    {
        "name": "codec/brute",
        "note": "把每种编码都试一遍",
        "seed": 0,
        "run": lambda q: codec.brute("&#x4f60;&#x597d;" * (1 if q else 4)),
    },
    {
        "name": "stego/grid",
        "note": "点阵图切格读位（报告 21）——640×640，图由 bench 现场生成",
        "seed": 0,
        "run": lambda q: stego.grid_read(_grid_fixture(40 if q else 64, 10)),
    },
    {
        "name": "hashcrypto/brute",
        "note": "掩码爆破吞吐：用不可能命中的 target 跑满，测纯吞吐",
        # 4 线程固定：本机 32 核时既稳定又接近用户那种 4 核机器的形态
        "seed": 0,
        "run": lambda q: hashcrypto.brute_force(
            "f" * 32, "?d" * (6 if q else 7), algo="md5", threads=4),
    },
]


# ---------------------------------------------------------------- 测量

def _quiet(fn):
    """跑 fn，把它的 stdout/stderr 吞掉。

    那几个函数会往 stderr 写分析提示（「有 1 段在和文モールス表里查不到」），
    基准自己的表格不能被它们冲乱。
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        return fn()


def digest(obj):
    """对返回值做稳定摘要：只回答「结果一样不一样」，不存整个结果。"""
    return hashlib.sha1(repr(obj).encode("utf-8", "replace")).hexdigest()[:12]


def measure(case, reps, quick):
    """重复跑 reps 次，返回 (中位, 最小, 最大, 结果摘要)。

    最大/最小要一起留着：**每项的自身波动不一样**。1.8 秒的任务散布 3%，
    0.4 毫秒的任务同样跑 5 次能差 5% —— 判断「有没有改善」时得用该项自己的
    波动当门槛，否则微基准天天报警。
    """
    run = lambda: case["run"](quick)

    # 预热一次：首次调用要付 import 缓存 / 编码表构建的钱，不该算进基准
    random.seed(case.get("seed", 0))
    _quiet(run)

    times = []
    result = None
    for _ in range(reps):
        random.seed(case.get("seed", 0))     # 同种子 = 同工作量
        t0 = time.perf_counter()
        result = _quiet(run)
        times.append(time.perf_counter() - t0)
    return statistics.median(times), min(times), max(times), digest(result)


def spread(med, best, worst):
    """一次测量内部的散布（%）。这就是这次测量自己的噪音下限。"""
    return (worst - best) / med * 100 if med else 0.0


def fmt_sec(x):
    if x >= 1:
        return "%.2fs" % x
    if x >= 0.001:
        return "%.1fms" % (x * 1000)
    return "%.2fms" % (x * 1000)


# ---------------------------------------------------------------- 机器指纹

def _machine():
    """本机指纹。**基线里的毫秒数绑死在机器上**，换台机器比没有意义。

    不记这个就没法区分两种「变慢」：一种是代码退化了（该查），另一种是
    换了台更慢的机器（无事发生）。同一条 `--compare` 输出，两种情况长得
    一模一样，全靠人记住当初在哪测的——靠不住。

    注意：`digest`（结果摘要）是**机器无关**的，同样的输入永远同样的输出。
    所以换机器时只该跳过耗时的快慢判断，摘要仍然要照常校验。
    """
    cpu = ""
    # Linux：/proc/cpuinfo 里有完整型号；platform.processor() 只给 "x86_64"。
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    if not cpu:
        # Windows：PROCESSOR_IDENTIFIER 才有 "AMD64 Family 25 Model 97 …"
        # 这种信息，platform.processor() 常常只有 "AMD64"。
        cpu = (os.environ.get("PROCESSOR_IDENTIFIER")
               or platform.processor() or platform.machine() or "?")
    return {
        "cpu": cpu.strip(),
        "logical_cores": os.cpu_count(),
        "os": ("%s %s" % (platform.system(), platform.release())).strip(),
        "python": platform.python_version(),
    }


_MACHINE_FIELDS = ("cpu", "logical_cores", "os", "python")


def _machine_line(m):
    return "%s / %s 逻辑核 / %s / Python %s" % (
        m.get("cpu") or "?", m.get("logical_cores") or "?",
        m.get("os") or "?", m.get("python") or "?")


def _machine_diffs(base_m, cur_m):
    """返回不同的字段名列表；空列表 = 同一台机器。"""
    return [k for k in _MACHINE_FIELDS if base_m.get(k) != cur_m.get(k)]


# ---------------------------------------------------------------- 两种模式

def do_measure(cases, reps, quick, save_path):
    mach = _machine()
    print("本机：%s" % _machine_line(mach))
    print("本机噪音 ±%.1f%%（小于它的变化不可信）%s"
          % (NOISE, "　[quick 模式，规模已缩小]" if quick else ""))
    print()
    print("%-18s %4s %9s %9s %7s  %s"
          % ("项目", "重复", "中位", "最小", "波动", "结果摘要"))
    print("-" * 72)
    out = {"noise": NOISE, "quick": quick, "machine": mach, "cases": {}}
    for case in cases:
        med, best, worst, dg = measure(case, reps, quick)
        out["cases"][case["name"]] = {
            "median": round(med, 6), "best": round(best, 6),
            "worst": round(worst, 6), "digest": dg, "note": case["note"],
        }
        print("%-18s %4d %9s %9s %6.1f%%  %s"
              % (case["name"], reps, fmt_sec(med), fmt_sec(best),
                 spread(med, best, worst), dg))
    print()

    if save_path:
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
        print("基线已存：%s（绑在本机：%s）" % (save_path, _machine_line(mach)))
        print("  换机器后请重新 --save，别拿这份的耗时判断快慢。")
    return 0


def do_compare(cases, reps, quick, base_path):
    with open(base_path, encoding="utf-8") as f:
        base = json.load(f)
    by_name = {c["name"]: c for c in cases}
    noise = base.get("noise", NOISE)
    warn_quick = "　[quick 模式，与全量基线不可比！]" if quick else ""

    # 先确认这份基线是不是本机测的。不是同一台机器时，秒数之间没有可比性
    # ——但 digest 仍然有意义（同样的输入永远同样的输出），所以只跳过快慢判断。
    cur_m = _machine()
    base_m = base.get("machine")
    machine_ok = True
    if not base_m:
        print("⚠ 这份基线没有机器信息（旧格式存的），无法确认是否本机。")
        print("    建议重新 --save 一次，之后换机器会被自动识别。")
        print()
    else:
        diffs = _machine_diffs(base_m, cur_m)
        if diffs:
            machine_ok = False
            print("⚠ 基线和本机不是同一台机器 —— 下面的耗时不可比，只校验结果摘要。")
            print("    基线：%s" % _machine_line(base_m))
            print("    本机：%s" % _machine_line(cur_m))
            for k in diffs:
                print("    差异 %-14s %s  →  %s" % (k, base_m.get(k), cur_m.get(k)))
            print("    要拿耗时说话，先在这台机器上 --save 一份新基线。")
            print()

    print("基线：%s（噪音 ±%.1f%%）%s" % (base_path, noise, warn_quick))
    print()
    print("%-18s %9s %9s %9s  %s"
          % ("项目", "基线", "本次", "变化", "结果"))
    print("-" * 70)

    failed = 0
    for name, b in base["cases"].items():
        case = by_name.get(name)
        if case is None:
            print("%-18s %9s %9s %9s  %s"
                  % (name, fmt_sec(b["median"]), "—", "—", "本次没有这一项"))
            continue
        med, best, worst, dg = measure(case, reps, quick)
        bmed = b["median"]
        delta = (med - bmed) / bmed * 100 if bmed else 0.0
        # 门槛 = max(全局噪音, 本次散布, 基线散布)。微基准的散布天生比大项大，
        # 只用一个全局常数会让它们每次都被误判成「变慢」。
        threshold = max(noise,
                        spread(med, best, worst),
                        spread(bmed, b.get("best", bmed), b.get("worst", bmed)))
        if dg != b["digest"]:
            verdict = "★ 结果变了！"
            failed += 1
        elif not machine_ok:
            verdict = "摘要一致（耗时不可比：换了机器）"
        elif abs(delta) <= threshold:
            verdict = "一致（±%.1f%% 内，无显著差异）" % threshold
        elif delta < 0:
            verdict = "一致，变快"
        else:
            verdict = "一致，变慢"
        print("%-18s %9s %9s %+8.1f%%  %s"
              % (name, fmt_sec(bmed), fmt_sec(med), delta, verdict))
    print()

    if failed:
        print("❌ %d 项的结果摘要和基线不同 —— 这次改动改变了行为，"
              "「变快」不成立，先查正确性。" % failed)
        return 1
    if not machine_ok:
        print("✅ 结果摘要全部一致。耗时差异未判断：基线不是这台机器测的。")
        return 0
    print("✅ 结果全部一致。每项按自己的波动范围判断，阈值以内的差异不算改善。")
    return 0


# ---------------------------------------------------------------- 入口

def main(argv):
    ap = argparse.ArgumentParser(description="puzzle-toolkit 性能基准")
    ap.add_argument("--only", default="", help="只跑名字里含这个子串的项")
    ap.add_argument("--reps", type=int, default=5, help="每项重复次数（默认 5）")
    ap.add_argument("--quick", action="store_true", help="缩小规模，开发迭代用")
    ap.add_argument("--save", default="", metavar="FILE", help="把这次结果存成基线")
    ap.add_argument("--compare", default="", metavar="FILE", help="跟基线比")
    ap.add_argument("--list", action="store_true", help="列出基准项")
    args = ap.parse_args(argv)

    if args.list:
        print("%-18s %s" % ("项目", "说明"))
        print("-" * 72)
        for c in CASES:
            print("%-18s %s" % (c["name"], c["note"]))
        return 0

    cases = CASES
    if args.only:
        cases = [c for c in CASES if args.only in c["name"]]
        if not cases:
            print("没有名字含 %r 的基准项" % args.only, file=sys.stderr)
            return 2

    if args.compare:
        return do_compare(cases, args.reps, args.quick, args.compare)
    return do_measure(cases, args.reps, args.quick, args.save)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
