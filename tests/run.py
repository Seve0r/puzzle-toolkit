#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跑 tests/dataset.json 里的测试用例。

用法：
    python3 tests/run.py              # 全跑，失败详单
    python3 tests/run.py -v           # 每条都打
    python3 tests/run.py --tag error  # 只跑某个标签
    python3 tests/run.py --id codec-basic-001

约定（对应 docs/testdata-prompt.md）：
  · expect.stdout            去掉末尾换行后**逐字符相等**
  · expect.stdout_contains   所有子串都出现在 stdout
  · expect.stderr_contains   所有子串都出现在 stderr
  · expect.exit              退出码相等
  · expect.unknown           跳过（数据集里明确标了"没把握"的条目）

fixtures 会先写到临时目录，用例以该目录为 cwd 执行，所以 `-f hello.txt`
这种相对路径能生效；脚本本身用绝对路径调用，不受 cwd 影响。
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(ROOT)
DEFAULT_DS = os.path.join(ROOT, "dataset.json")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check(case, tmp, verbose=False):
    """返回 (状态, 说明, 实际stdout, 实际stderr)。状态: pass/fail/skip。"""
    exp = case.get("expect") or {}
    if "unknown" in exp:
        return "skip", "数据集标注 unknown：%s" % exp["unknown"], "", ""

    script = os.path.join(PROJ, case["script"])
    if not os.path.exists(script):
        return "fail", "脚本不存在：%s" % script, "", ""

    cmd = [sys.executable, script] + list(case.get("args") or [])
    kwargs = {"cwd": tmp, "capture_output": True, "timeout": 180}
    if case.get("stdin") is not None:
        kwargs["input"] = case["stdin"]
        kwargs["text"] = True
    else:
        kwargs["stdin"] = subprocess.DEVNULL

    try:
        r = subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        return "fail", "超时（180s）", "", ""

    out = r.stdout or ""
    err = r.stderr or ""
    if isinstance(out, bytes):
        out = out.decode("utf-8", "replace")
    if isinstance(err, bytes):
        err = err.decode("utf-8", "replace")

    problems = []
    if "exit" in exp and r.returncode != exp["exit"]:
        problems.append("exit=%d 期望 %d" % (r.returncode, exp["exit"]))
    if "stdout" in exp:
        if out.rstrip("\n") != exp["stdout"].rstrip("\n"):
            problems.append("stdout 不符")
    if "stdout_contains" in exp:
        for s in exp["stdout_contains"]:
            if s not in out:
                problems.append("stdout 缺 %r" % s)
    if "stderr_contains" in exp:
        for s in exp["stderr_contains"]:
            if s not in err:
                problems.append("stderr 缺 %r" % s)
    if not problems and "stdout" not in exp and "stdout_contains" not in exp:
        # 没给任何 stdout 断言时只校验 exit —— 提醒一下，不算失败
        pass

    if problems:
        return "fail", "; ".join(problems), out, err
    return "pass", "", out, err


def main(argv):
    ds_path = DEFAULT_DS
    only_tag = None
    only_id = None
    verbose = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-v", "--verbose"):
            verbose = True
        elif a == "--tag":
            i += 1
            only_tag = argv[i]
        elif a == "--id":
            i += 1
            only_id = argv[i]
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            ds_path = a
        i += 1

    data = load(ds_path)
    cases = data.get("cases") or []
    if only_tag:
        cases = [c for c in cases if only_tag in (c.get("tags") or [])]
    if only_id:
        cases = [c for c in cases if c.get("id") == only_id]

    tmp = tempfile.mkdtemp(prefix="ptest-")
    try:
        for f in data.get("fixtures") or []:
            path = os.path.join(tmp, f["name"])
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "wb") as fp:
                fp.write(base64.b64decode(f["content_b64"]))

        stat = {"pass": 0, "fail": 0, "skip": 0}
        failures = []
        for c in cases:
            st, note, out, err = check(c, tmp, verbose)
            stat[st] += 1
            if st == "fail":
                failures.append((c, note, out, err))
            if verbose:
                mark = {"pass": "✅", "fail": "❌", "skip": "⏭"}[st]
                print("%s %-24s %s" % (mark, c.get("id"), note))

        total = sum(stat.values())
        print("\n" + "=" * 70)
        print("总计 %d 条：通过 %d / 失败 %d / 跳过 %d"
              % (total, stat["pass"], stat["fail"], stat["skip"]))
        if failures:
            print("\n" + "=" * 70)
            print("失败详单（%d 条）" % len(failures))
            for c, note, out, err in failures:
                print("\n▸ %s  [%s]" % (c.get("id"), c.get("script")))
                print("  命令: %s %s" % (c.get("script"), " ".join(c.get("args") or [])))
                print("  问题: %s" % note)
                print("  期望: %s" % json.dumps(c.get("expect"), ensure_ascii=False))
                print("  实际 stdout: %r" % (out.rstrip("\n")[:200]))
                if err.strip():
                    print("  实际 stderr: %r" % (err.strip()[:200]))
                if c.get("note"):
                    print("  用例说明: %s" % c["note"])
        return 0 if stat["fail"] == 0 else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
