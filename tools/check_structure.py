#!/usr/bin/env python3
"""校验 docs/structure.md 与源码是否还一致。

structure.md 里那些行号、对象数、分区范围全是**派生数据**：改一行代码就可能
让它们集体漂。AGENTS.md 写着「别手算偏移，一律用 ast 重新校准」——这个脚本把
那条例行变成一条命令。

**只读，不改任何文件。** 发现不一致就打印「文档写的 / 实测的」，然后以非零
退出码结束，适合挂在提交前。

用法：
    python3 tools/check_structure.py          # 只报不一致
    python3 tools/check_structure.py -v       # 逐项列出对比
    python3 tools/check_structure.py --doc X  # 换一份文档（默认 docs/structure.md）

退出码：0 = 全部一致；1 = 有漂移；2 = 读不到文件 / 解析失败。

踩过的坑（也就是这个脚本要防的）：
  · `codec.py` 的 main 从 347 漂到 356 再到 370 行，连着三轮没人发现；
  · ui.py 里加了几行后，结构图那 8 个 `L数字` 全部偏 5；
  · 「顶层对象」这一列的口径其实是 `len(ast.body)`（顶层**语句**数，含 import
    和常量赋值），不是「顶层 def/class 个数」——按后者算 codec 会得 126 而
    文档写 181，很容易把对的改成错的。脚本按真实口径校验。
"""
import argparse
import ast
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DOC = os.path.join(ROOT, "docs", "structure.md")

# 脚本总表的行顺序，跟文档一致
SCRIPTS = ["codec.py", "classic.py", "hashcrypto.py", "stego.py",
           "num.py", "ui.py", "ui_params.py"]

# 章节标题 -> 该章节引用的脚本（正文行号要按这个归属去校对）
SECTION_MAP = [
    ("## 一、`codec.py`", "codec.py"),
    ("## 二、`classic.py`", "classic.py"),
    ("## 三、`hashcrypto.py`", "hashcrypto.py"),
    ("## 四、`stego.py`", "stego.py"),
    ("## 五、`num.py`", "num.py"),
    ("### `ui.py`", "ui.py"),
    ("### `ui_params.py`", "ui_params.py"),
]

ANCHOR_RE = re.compile(r"^# -{10,}")


def analyze(path):
    """把一个脚本量成结构图需要的那些数。"""
    with open(path, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src)
    lines = src.splitlines()
    tops = tree.body
    defs = [n for n in tops if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    longest = max(defs, key=lambda n: n.end_lineno - n.lineno + 1) if defs else None
    return {
        "lines": len(lines),
        "stmts": len(tops),          # 「顶层对象」的真实口径
        "defs": len(defs),
        "anchors": [i + 1 for i, l in enumerate(lines) if ANCHOR_RE.match(l)],
        "src_lines": lines,
        "longest": (longest.name, longest.end_lineno - longest.lineno + 1) if longest else None,
        "tops": tops,
    }


def _fmt_longest(info):
    if not info["longest"]:
        return "—"
    return "`%s` %d 行" % info["longest"]


# ---------------------------------------------------------------- 各类检查

def check_summary_table(doc, infos, problems, report):
    """第一节那张「脚本 / 行数 / 顶层对象 / 分区 / 最长函数 / 职责」。"""
    for name in SCRIPTS:
        info = infos.get(name)
        if info is None:
            problems.append("表格要的 %s 不存在" % name)
            continue
        m = re.search(
            r"\|\s*`%s`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\S+?)\s*\|\s*([^|]+?)\s*\|"
            % re.escape(name), doc)
        if not m:
            problems.append("脚本总表里找不到 `%s` 那一行" % name)
            continue
        d_lines, d_stmts, d_sec, d_longest = (int(m.group(1)), int(m.group(2)),
                                             m.group(3), m.group(4).strip())
        real_sec = str(len(info["anchors"])) if info["anchors"] else "—"
        want = (info["lines"], info["stmts"], real_sec, _fmt_longest(info))
        got = (d_lines, d_stmts, d_sec, d_longest)
        if want != got:
            for label, w, g in zip(("行数", "顶层对象", "分区", "最长函数"), want, got):
                if w != g:
                    problems.append("脚本总表 `%s` 的%s：文档 %s，实测 %s"
                                    % (name, label, g, w))
        else:
            report("  ✅ %s" % name)


def sections_of(doc):
    """把文档按 SECTION_MAP 切成 [(脚本名, 章节正文)]。

    分区表校验和正文行号校验都要「只看属于这个文件的章节」—— 全文盲搜会把
    codec 的区间和 classic 的区间混在一起，对不上才怪。
    """
    marks = [(doc.find(t), f) for t, f in SECTION_MAP]
    marks = [(i, f) for i, f in marks if i >= 0]
    marks.sort()
    out = []
    for idx, (start, fname) in enumerate(marks):
        end = marks[idx + 1][0] if idx + 1 < len(marks) else len(doc)
        out.append((fname, doc[start:end]))
    return out


def check_section_tables(doc, infos, problems, report):
    """各章节的分区表：`| 区 | 行范围 | 行数 | … |`。

    只校验有锚点的脚本；`num.py` 没有分区表。
    """
    secs = dict(sections_of(doc))
    for name in SCRIPTS:
        info = infos.get(name)
        if not info or not info["anchors"]:
            continue
        sec = secs.get(name)
        if sec is None:
            problems.append("structure.md 里找不到 %s 的章节" % name)
            continue
        anchors = info["anchors"]
        rows = [(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                for m in re.finditer(
                    r"^\|\s*[^|]+?\s*\|\s*(\d+)[–-](\d+)\s*\|\s*\*{0,2}(\d+)\*{0,2}\s*\|",
                    sec, re.M)]
        # 表里可能多一行「文件头」（从第 1 行开始、到第一个锚点前）。codec 有，
        # classic / hashcrypto / stego 没有 —— 按文档实际形态决定要不要补。
        expect = []
        if rows and rows[0][0] == 1 and anchors[0] > 1:
            expect.append((1, anchors[0] - 1, anchors[0] - 1))
        for i, a in enumerate(anchors):
            end = anchors[i + 1] - 1 if i + 1 < len(anchors) else info["lines"]
            expect.append((a, end, end - a + 1))
        if not rows:
            # 该章节压根没写分区表（ui.py / ui_params.py 就是这样），跳过。
            report("  – %s 没有分区表，跳过" % name)
            continue
        if len(rows) != len(expect):
            problems.append("%s 的分区表行数：文档 %d 行，实际有 %d 个锚点"
                            % (name, len(rows), len(expect)))
            continue
        bad = 0
        for (ga, gb, gn), (ea, eb, en) in zip(rows, expect):
            if (ga, gb, gn) != (ea, eb, en):
                problems.append("%s 分区表：文档 %d–%d（%d 行），实测 %d–%d（%d 行）"
                                % (name, ga, gb, gn, ea, eb, en))
                bad += 1
        if not bad:
            report("  ✅ %s（%d 区）" % (name, len(expect)))


def check_prose_stats(doc, infos, problems, report):
    """正文那句「N 行 / M 个顶层对象 / K 个分区」。"""
    pat = re.compile(r"(\d+) 行 / (\d+) 个顶层对象 / (?:(\d+) 个分区|\*\*无分区\*\*)")
    index = {name: infos[name] for name in infos}
    for m in pat.finditer(doc):
        d_lines, d_stmts = int(m.group(1)), int(m.group(2))
        d_sec = m.group(3)          # None 表示文档写的是「无分区」
        cand = [n for n, i in index.items() if i["lines"] == d_lines]
        if len(cand) != 1:
            problems.append("正文统计「%d 行 / %d 个顶层对象」对不上任何脚本的行数"
                            % (d_lines, d_stmts))
            continue
        info = index[cand[0]]
        real_sec = len(info["anchors"]) or None
        if d_stmts != info["stmts"]:
            problems.append("正文统计 %s：文档写 %d 个顶层对象，实测 %d"
                            % (cand[0], d_stmts, info["stmts"]))
        elif (d_sec is None) != (real_sec is None):
            problems.append("正文统计 %s：分区有无不一致（实测 %s 个分区）"
                            % (cand[0], real_sec or 0))
        elif real_sec is not None and int(d_sec) != real_sec:
            problems.append("正文统计 %s：文档写 %s 个分区，实测 %s"
                            % (cand[0], d_sec, real_sec))
        else:
            report("  ✅ %s" % cand[0])


def check_line_refs(doc, infos, problems, report):
    """正文里散落的 `函数名`（L数字），逐个核对那一行是不是该函数。"""
    secs = sections_of(doc)
    if not secs:
        problems.append("认不出任何章节，structure.md 结构变了？")
        return
    ref_re = re.compile(r"`([A-Za-z_][A-Za-z0-9_.()]*)`[^\n]{0,14}?（?L(\d+)(?!\s*[–-])")
    for fname, sec in secs:
        lines = infos[fname]["src_lines"]
        bad = 0
        for m in ref_re.finditer(sec):
            raw = m.group(1)
            key = raw.split("(")[0].split(".")[-1]
            ln = int(m.group(2))
            if ln <= len(lines) and key in lines[ln - 1]:
                continue
            # 找出它现在真正在哪
            real = [i + 1 for i, l in enumerate(lines)
                    if re.match(r"\s*(async\s+)?def\s+%s\b" % re.escape(key), l)
                    or re.match(r"\s*function\s+%s\b" % re.escape(key), l)
                    or re.match(r"\s*(async\s+)?function\s+%s\b" % re.escape(key), l)]
            problems.append("%s 里 `%s`：文档写 L%d，实际在 %s"
                            % (fname, key, ln,
                               ("L" + "/L".join(map(str, real))) if real else "找不到该函数"))
            bad += 1
        if not bad:
            report("  ✅ %s（%d 处引用）" % (fname, len(ref_re.findall(sec))))


# ---------------------------------------------------------------- 入口

def main(argv):
    ap = argparse.ArgumentParser(description="校验 docs/structure.md 与源码一致")
    ap.add_argument("--doc", default=DEFAULT_DOC, help="要校验的文档")
    ap.add_argument("-v", "--verbose", action="store_true", help="逐项列出")
    args = ap.parse_args(argv)

    def report(msg):
        if args.verbose:
            print(msg)

    if not os.path.isfile(args.doc):
        print("找不到文档：%s" % args.doc, file=sys.stderr)
        return 2
    with open(args.doc, encoding="utf-8") as f:
        doc = f.read()

    infos = {}
    for name in SCRIPTS:
        path = os.path.join(ROOT, name)
        if not os.path.isfile(path):
            print("找不到脚本：%s" % path, file=sys.stderr)
            return 2
        try:
            infos[name] = analyze(path)
        except SyntaxError as e:
            print("%s 语法错误，没法量：%s" % (name, e), file=sys.stderr)
            return 2

    problems = []
    print("校验 %s" % os.path.relpath(args.doc, ROOT))
    print("[1] 脚本总表（行数 / 顶层对象 / 分区 / 最长函数）")
    check_summary_table(doc, infos, problems, report)
    print("[2] 各章节分区表的行范围")
    check_section_tables(doc, infos, problems, report)
    print("[3] 正文「N 行 / M 个顶层对象 / K 个分区」")
    check_prose_stats(doc, infos, problems, report)
    print("[4] 正文里散落的函数行号")
    check_line_refs(doc, infos, problems, report)

    print()
    if not problems:
        print("✅ 全部一致")
        return 0
    # 去重（同一处可能被多条规则各报一次）
    seen = set()
    uniq = []
    for p in problems:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    print("❌ 发现 %d 处不一致：" % len(uniq))
    for p in uniq:
        print("   · %s" % p)
    print("\n按 AGENTS.md：一律用 ast 重新校准，别手算偏移。")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
