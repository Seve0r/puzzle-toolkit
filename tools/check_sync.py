#!/usr/bin/env python3
"""校验仓库版与 skill 版两份副本是否一致（`~/puzzle-toolkit` ↔ `~/.dsh/skills`）。

这些文件各有两份，必须逐字节相同：仓库版是给人 clone 的，skill 版是 dsh 里
真正被调用的。两边一旦分叉，**用户在不同地方跑会得到不同结果**，而这种不一致
极难察觉 —— 比 bug 本身更糟。

**只读，不改任何文件。** 用法：

    python3 tools/check_sync.py          # 只报不一致
    python3 tools/check_sync.py -v       # 逐项列出
    python3 tools/check_sync.py --skills /别的/路径

退出码：0 = 全部一致；1 = 有分叉或缺失；2 = 环境不对（比如没有 skills 目录）。

它比手写 `md5sum` 循环多查三件事：

  1. **不一致时告诉你差在哪**：各多少行、仓库独有几行、skill 独有几行，
     再附几行样例。光说「不一致」还得自己 diff。
  2. **skill 侧独有内容**（`diff | grep -c '^>'` 那个检查）。同步是 `cp` 覆盖，
     skill 里若有仓库没有的内容会被**静默删掉**，所以这一项单独警告。
  3. **未登记的文件**：仓库里新加了脚本或 docs/*.md，但同步表没跟着更新 ——
     这种遗漏完全无声，只能靠扫目录发现。

为什么值得单独写：AGENTS.md 记过一次事故 —— 改了 `docs/codec.md` 118 行、
`docs/classic.md` 45 行、`docs/hashcrypto.md` 46 行，`SKILL.md` 全是旧的，
新功能在 skill 侧完全不存在，等于白做。**脚本不同步至少还会报错，
文档缺了完全没动静。**
"""
import argparse
import difflib
import filecmp
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SKILLS = os.path.expanduser("~/.dsh/skills")

# 脚本名 -> skill 目录名
SKILL_OF = {
    "codec": "codec-toolkit",
    "classic": "classic-cipher",
    "hashcrypto": "hash-crypto",
    "stego": "stego-toolkit",
    "num": "num-toolkit",
}

# (仓库相对路径, skill 相对路径)
SYNC = (
    [(n + ".py", "%s/scripts/%s.py" % (SKILL_OF[n], n)) for n in
     ("codec", "classic", "hashcrypto", "stego", "num")]
    + [("data/words.txt", "classic-cipher/scripts/data/words.txt")]
    + [("docs/%s.md" % n, "%s/SKILL.md" % SKILL_OF[n]) for n in
       ("codec", "classic", "hashcrypto", "stego", "num")]
)

# 故意不分发的：界面是仓库专属（skill 里没有 UI），结构图/提示词是维护者用的。
# 列在这里是为了让「未登记」检查不把它们当成漏登记。
NOT_SYNCED = {
    "ui.py", "ui_params.py",
    "docs/structure.md", "docs/testdata-prompt.md",
}


def _diff_summary(a_path, b_path):
    """两份文本差在哪：行数、各自独有几行、仓库独有的样例。"""
    with open(a_path, encoding="utf-8", errors="replace") as f:
        al = f.read().splitlines()
    with open(b_path, encoding="utf-8", errors="replace") as f:
        bl = f.read().splitlines()
    sm = difflib.SequenceMatcher(None, al, bl)
    only_a = only_b = 0
    sample_a, sample_b = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("delete", "replace"):
            only_a += i2 - i1
            sample_a.extend(al[i1:i2][:3])
        if tag in ("insert", "replace"):
            only_b += j2 - j1
            sample_b.extend(bl[j1:j2][:3])
    return {"n_a": len(al), "n_b": len(bl), "only_a": only_a, "only_b": only_b,
            "sample_a": sample_a[:3], "sample_b": sample_b[:3]}


def check_pairs(skills, problems, warns, report):
    """逐个比对同步表里的 11 对。"""
    for rel, sk in SYNC:
        a = os.path.join(ROOT, rel)
        b = os.path.join(skills, sk)
        if not os.path.isfile(a):
            problems.append("仓库里缺 %s" % rel)
            continue
        if not os.path.isfile(b):
            problems.append("%s 在 skill 侧不存在：%s" % (rel, sk))
            continue
        if filecmp.cmp(a, b, shallow=False):
            report("  ✅ %-20s → %s" % (rel, sk))
            continue
        d = _diff_summary(a, b)
        problems.append(
            "%s 与 skill 版不一致：仓库 %d 行 / skill %d 行，"
            "仓库独有 %d 行、skill 独有 %d 行"
            % (rel, d["n_a"], d["n_b"], d["only_a"], d["only_b"]))
        if d["only_b"]:
            # 同步是 cp 覆盖，skill 独有的内容会被删掉 —— 这条必须单独提醒
            warns.append(
                "%s 的 skill 版有 %d 行是仓库版没有的，直接 cp 会丢掉：\n%s"
                % (rel, d["only_b"],
                   "\n".join("       + " + s for s in d["sample_b"])))
        report("  ❌ %-20s → %s" % (rel, sk))


def check_unregistered(skills, warns, report):
    """仓库里新加了脚本/文档，但同步表没登记。"""
    known = {rel for rel, _ in SYNC} | NOT_SYNCED
    found = []
    for f in sorted(os.listdir(ROOT)):
        if f.endswith(".py") and f not in known:
            found.append(f)
    docs = os.path.join(ROOT, "docs")
    if os.path.isdir(docs):
        for f in sorted(os.listdir(docs)):
            if f.endswith(".md") and ("docs/" + f) not in known:
                found.append("docs/" + f)
    for f in found:
        warns.append(
            "%s 不在同步表里 —— 如果它是给 skill 用的，请在 tools/check_sync.py "
            "的 SYNC 里登记；如果是仓库专属（像 ui.py），加进 NOT_SYNCED。" % f)
    if not found:
        report("  ✅ 没有未登记的文件")


def main(argv):
    ap = argparse.ArgumentParser(description="校验仓库版与 skill 版是否一致")
    ap.add_argument("--skills", default=DEFAULT_SKILLS, help="skill 根目录")
    ap.add_argument("-v", "--verbose", action="store_true", help="逐项列出")
    args = ap.parse_args(argv)

    def report(msg):
        if args.verbose:
            print(msg)

    if not os.path.isdir(args.skills):
        print("找不到 skill 目录：%s" % args.skills, file=sys.stderr)
        print("（换机器或没装 skill 时这一项没法校验，不是仓库的问题）", file=sys.stderr)
        return 2

    problems, warns = [], []
    print("校验双副本：%s  ↔  %s" % (os.path.basename(ROOT), args.skills))
    print("[1] 同步表（%d 对：脚本 / 词表 / 文档）" % len(SYNC))
    check_pairs(args.skills, problems, warns, report)
    print("[2] 有没有新文件忘了登记")
    check_unregistered(args.skills, warns, report)

    print()
    rc = 0
    if problems:
        rc = 1
        print("❌ %d 处不一致：" % len(problems))
        for p in problems:
            print("   · %s" % p)
    if warns:
        rc = 1
        print()
        print("⚠ %d 条提醒：" % len(warns))
        for w in warns:
            print("   · %s" % w)
    if rc == 0:
        print("✅ 全部一致")
    else:
        print("\n按 AGENTS.md：改完一份就立刻覆盖另一份，然后重新跑这个脚本。")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
