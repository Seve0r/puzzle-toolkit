#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
puzzle-toolkit 的本地图形界面（浏览器版，纯标准库）。

用法：
  python3 ui.py                     起服务并自动打开浏览器
  python3 ui.py --port 9000         换端口
  python3 ui.py --no-browser        不自动开浏览器（调试/远程用）

为什么是网页而不是 Tkinter：
  这个工具箱要能在任何一台装了 Python 的机器上直接跑。Tkinter 虽然也是标准库，
  但不少 Linux 发行版把 python3-tk 拆成了单独的包（本机就没有），而且中文字体、
  DPI 缩放各平台表现不一。网页版只依赖 http.server，界面用浏览器渲染，字体和
  缩放交给浏览器，反而更稳。手机上同一个局域网也能用。

设计约束：
  ★ 只 import 现有脚本，绝不复制任何解码逻辑。改了 codec.py，界面立刻跟着变。
  ★ 解码器会用 sys.stderr 输出提示（损失率、查不到的段…），浏览器里没有终端，
    这些必须接住显示出来，否则「解不出」和「解得不准」就分不清了。
"""

import argparse
import base64
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import codec       # noqa: E402  必须在本文件同目录
import classic     # noqa: E402
import hashcrypto  # noqa: E402
import stego       # noqa: E402
import num         # noqa: E402
import ui_params   # noqa: E402  参数表也在这里


# ---------------------------------------------------------------- 进制面板

def _run_num(payload):
    """一个数 → 2..36 的全部写法。

    只取**第一个非空行**：35 行结果已经够占地方，多值叠起来就没法看了；
    批量转换去命令行（`num.py -f 文件`）。多行时会明说只转了第一个。
    """
    text = payload.get("text") or ""
    params = payload.get("params") or {}
    frm = params.get("from")
    base_from = None
    if frm not in (None, "", "auto"):
        try:
            base_from = int(frm)
        except (TypeError, ValueError):
            return {"ok": False, "error": "输入进制要是 2..36"}
        if not (2 <= base_from <= 36):
            return {"ok": False, "error": "输入进制要是 2..36"}

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return {"ok": False, "error": "先输入一个数"}
    tok = lines[0]
    try:
        n, used, auto = num.parse_num(tok, base_from)
    except ValueError as e:
        return {"ok": False, "error": "解析不了 %r：%s" % (tok, e)}

    note = ""
    if len(lines) > 1:
        note = "只转换了第一个数（%s）；批量请用命令行 num.py -f" % tok
    if auto and used == 10:
        body = tok.lstrip("+-").lower()
        if len(body) >= 8 and len(body) % 8 == 0 and set(body) <= {"0", "1"}:
            tip = "看着像二进制串，要按二进制算请把「输入进制」选成二进制"
            note = tip + ("　" + note if note else "")
    return {"ok": True, "token": tok, "src": used, "auto": auto,
            "pairs": [[b, num.to_base(n, b)] for b in range(2, 37)],
            "note": note}


# ---------------------------------------------------------------- 后端逻辑

def _as_text(value):
    """解码器有时返回 str、有时返回 bytes，统一转成能放进 JSON 的文本。"""
    if isinstance(value, bytes):
        return codec.as_text(value)
    return "" if value is None else str(value)


# 显示名微调：注册顺序里的第一个名字未必是最好认的。
_UI_LABEL = {
    "base16": "hex",   # 十六进制，日常都叫 hex
}


# 「原文格式」预设 -> 真正的掩码参数。第一次用 Mask 的人不该被「掩码语法」挡住，
# 选一个「8 位数字」就能直接跑。
MASK_PRESETS = {
    "d4":     {"len": 4,  "charset": "digits"},
    "d6":     {"len": 6,  "charset": "digits"},
    "d8":     {"len": 8,  "charset": "digits"},
    "d10":    {"len": 10, "charset": "digits"},
    "lower6": {"len": 6,  "charset": "lower"},
}


def _encoding_names():
    """所有编码，**按「同一个编码概念」去重**，一项只出现一次。

    注册表里同一个函数常挂好几个名字（`@dec_name("base64", "b64")`），直接
    列出来会让下拉框一半是重复项 —— 70 个解码器名字其实只有 37 个函数。

    ★ 不能简单按函数分组：解码函数和编码函数是两个不同的对象
      （`_d_b64` / `_e_b64`），那样会把 base64 拆成「只能解码的 base64」和
      「只能编码的 base64」两条。正确做法是按**共享名字**把两侧连起来：
      `@dec_name("base64","b64")` 和 `@enc_name("base64","b64")` 共享这两个名字，
      所以它们属于同一个概念。用并查集做连通分量。

    正式名取「注册顺序里最早出现的那个」，也就是装饰器的第一个参数。
    别名留着给前端做搜索（打 b64 也能找到 base64）。
    """
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:       # 路径压缩
            parent[x], x = root, parent[x]
        return root

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # 同一张表里，指向同一个函数的名字都属于同一个概念
    for table in (codec.DECODERS, codec.ENCODERS):
        by_fn = {}
        for name, fn in table.items():
            by_fn.setdefault(id(fn), []).append(name)
        for names in by_fn.values():
            for n in names[1:]:
                union(names[0], n)

    dec, enc = codec.DECODERS, codec.ENCODERS
    order = list(dec) + [n for n in enc if n not in dec]
    seen = {}
    out = []
    for name in order:
        root = find(name)
        e = seen.get(root)
        if e is None:
            e = {"name": name, "aliases": [], "dec": False, "enc": False}
            seen[root] = e
            out.append(e)
        elif name != e["name"] and name not in e["aliases"]:
            e["aliases"].append(name)
        if name in dec:
            e["dec"] = True
        if name in enc:
            e["enc"] = True
    out.sort(key=lambda e: e["name"])
    # 注册顺序第一个未必是最好认的名字。`base16` 其实是十六进制，日常都叫
    # `hex`（上一版直接把 hex 藏成别名，下拉框里反而找不到了）。
    for e in out:
        e["label"] = _UI_LABEL.get(e["name"], e["name"])
        if e["label"] in e["aliases"]:      # 显示名已经是它，别名里别重复列
            e["aliases"].remove(e["label"])
    return out


def _run_subcommand(module, action, params, operand, extra=None):
    """跑 `classic.py` / `hashcrypto.py` / `stego.py` 的子命令。

    ★ 为什么不直接调各个函数：它们的签名五花八门 —— `caesar()` 返回
      `[(key, out)]`、`atbash()` 返回 `str`、`identify()` 返回 `[(name, desc)]`、
      `xor_single()` 返回 `[(score, key, bytes)]`；而且 `main()` 里那套子命令
      分发（参数名、默认值、互斥关系）要重写一遍，很容易漏。

      直接跑 `main()`、把它的 stdout 接过来，拿到的是**和命令行逐字节相同**
      的输出 —— 用户在界面里看到的，就是他在终端里会看到的那些东西。
      参数照样由界面控件收集，翻译成 argv 而已。

    `operand` 是主输入（文本，或 stego 的文件路径）；`extra` 是不带 flag 的
    附加位置参数（例如 stego 的 `-n 6` 这类用不到，留个口子）。
    """
    # 主输入必须紧跟子命令：三个脚本的 main() 都按「argv[0]=子命令、argv[1]=主输入」
    # 取参数，而选项由各自的 opt() 按名字查找、吃掉，和位置无关。
    # 原先拼成 [...选项..., 主输入]，于是 stego 把 `--cols` 当成了文件名。
    argv = [action] + ([operand] if operand else [])
    for k, v in (params or {}).items():
        if v is True:
            argv.append("--" + k)          # check 类型：出现即为真
        elif v is False or v is None or v == "":
            continue
        else:
            argv += ["--" + k, str(v)]
    if extra:
        argv += list(extra)

    # stdout 和 stderr 分开收：脚本按约定「结果走 stdout、分析走 stderr」，
    # 界面上前者进结果框、后者进底部提示条。混在一起收的话，用户对着结果框
    # 里那堆网格参数/得分/路径，根本挑不出哪一行才是答案。
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    old_argv = sys.argv
    code = 0
    try:
        sys.argv = [module.__name__ + ".py"] + argv
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            try:
                module.main()
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            except Exception as e:          # 脚本没接住的异常，别让界面白屏
                err_buf.write("\n执行出错：%s: %s" % (type(e).__name__, e))
                code = 1
    finally:
        sys.argv = old_argv

    out = out_buf.getvalue().rstrip("\n")
    notes = err_buf.getvalue().rstrip("\n")
    both = out or notes
    return {"ok": code == 0, "result": out, "log": notes,
            "error": "" if code == 0 else (both.splitlines()[-1] if both else "执行失败")}


def _run_stego(action, params, payload):
    """stego 的全部子命令都吃文件路径，而且多数要**原始字节**。

    ★ 界面原先用 `file.text()` 读文件 —— 那是把字节当 UTF-8 文本解码，
      对 PNG / MP3 会直接损坏数据（再把字符串写回去，字节就变了）。
      所以这里收前端传来的 base64，落地成临时文件，交给 stego，用完删掉。
    """
    b64 = payload.get("file_b64")
    if not b64:
        return {"ok": False, "error": "这个功能需要先选一个文件"}
    try:
        raw = base64.b64decode(b64)
    except Exception as e:
        return {"ok": False, "error": "文件数据解析失败：%s" % e}

    suffix = os.path.splitext(payload.get("filename") or "")[1] or ".bin"
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        res = _run_subcommand(stego, action, params, path)
        # spec 会生成 PNG 但只把路径 print 出来，界面拿到一串文字没意义。
        # 顺手把图读成 base64 一起返回，前端直接 <img> 显示。
        if action == "spec" and res.get("ok"):
            out_path = (res.get("result") or "").strip().splitlines()
            out_path = out_path[-1].strip() if out_path else ""
            if out_path and os.path.isfile(out_path):
                with open(out_path, "rb") as f:
                    res["image_b64"] = base64.b64encode(f.read()).decode()
                res["image_name"] = os.path.basename(out_path)
        return res
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _run_mojibake(text, payload, log):
    """mojibake 的四条通路：显式编码对 / --best / --deep / 普通。

    普通解码器只有一个入口 `f(text)`，但 mojibake 在命令行里还有
    `--from/--to`、`--best`、`--deep`。命令行能靠 main() 分流，这里必须自己判断。

    优先级：给了 --from/--to 就完全不猜（最可靠），其次 --best / --deep。

    ★ 普通模式失败时，`_d_mojibake()` 抛的 ValueError 里其实**带着最佳猜测**
      （"最佳猜测（? = 缺失处，不可全信）：…"）。只把它当错误塞进提示区的话，
      结果区一片空白，用户还得去提示里手抄。所以这里额外解析出猜测，作为
      `partial` 字段交给前端填进结果区。
    """
    src = (payload.get("from") or "").strip()
    tgt = (payload.get("to") or "").strip()
    if src or tgt:
        s = src or "gb18030"
        t = tgt or "utf-8"
        try:
            out = codec.mojibake_explicit(text, s, t)
        except ValueError as e:
            # 显式指定是最严格的方式：只要有一个字节不属于该编码就整体失败。
            # 很多「解不开」其实是数据本身缺了字节，不是方向填错了。
            return {"ok": False,
                    "error": "%s\n\n显式指定编码对不做任何容错，一个字节不对就整体失败。"
                             "若怀疑数据本身有损坏，把「还原模式」换成「最佳猜测」。"
                             % e,
                    "log": log.getvalue()}
        log.write("按 %s 编回字节 → 按 %s 解%s"
                  % (s, t, "（未填的那侧用了默认值）" if not (src and tgt) else ""))
        return {"ok": True, "result": out.replace("\ufffd", "?"),
                "log": log.getvalue()}

    deep = payload.get("deep")
    if payload.get("best"):
        out, ratio, bad, enc = codec.mojibake_best(text)
        if ratio > 0:
            log.write("损失 %.1f%%（%d 处缺失，假设 %s）"
                      % (ratio * 100, bad, enc))
        else:
            log.write("按 %s 还原，完整无损" % enc)
        return {"ok": True, "result": out.replace("\ufffd", "?"),
                "log": log.getvalue()}

    if deep is not None:
        out, layers, used = codec.mojibake_deep(text, int(deep))
        lines = []
        for n, (enc, ratio, rd) in enumerate(layers, 1):
            lines.append("第 %d 层  %-12s 损失 %5.1f%%  可读率 %3.0f%%%s"
                         % (n, enc, ratio * 100, rd * 100,
                            "  ←采信" if n == used else ""))
        lines.append("采信第 %d 层（可读率 %.0f%%，阈值 %d%%）"
                     % (used, codec.readability(out) * 100, int(deep)))
        log.write("\n".join(lines))
        return {"ok": True, "result": out.replace("\ufffd", "?"),
                "log": log.getvalue()}

    try:
        return {"ok": True, "result": _as_text(codec.DECODERS["mojibake"](text)),
                "log": log.getvalue()}
    except ValueError as e:
        msg = str(e)
        guess = None
        try:
            guess, _r, _b, _e = codec.mojibake_best(text)
            guess = guess.replace("\ufffd", "?")
        except Exception:
            pass
        return {"ok": False, "error": msg, "partial": guess,
                "log": log.getvalue()}


def run_action(payload):
    """执行一次请求。所有异常都转成 {"ok": false, "error": ...}，不让界面白屏。"""
    action = (payload.get("action") or "").strip()
    text = payload.get("text")
    if text is None:
        text = ""
    name = (payload.get("name") or "").strip()
    tab = (payload.get("tab") or "codec").strip()

    if tab == "num":
        return _run_num(payload)

    if tab == "stego":
        return _run_stego(action, payload.get("params") or {}, payload)

    # classic / hashcrypto 走「跑子命令」这条路，输出和命令行一致
    if tab in ("classic", "hashcrypto"):
        module = {"classic": classic, "hashcrypto": hashcrypto}[tab]
        params = dict(payload.get("params") or {})
        if tab == "hashcrypto" and action == "mask":
            # 「原文格式」是界面上给人选的，先翻译成真正的掩码参数
            preset = params.pop("preset", None)
            if preset in MASK_PRESETS:
                params.update(MASK_PRESETS[preset])
            elif params.get("mask") and "len" in params:
                params.pop("len")          # 两者都给了就让掩码优先
        return _run_subcommand(module, action, params, text)

    # 解码器会往 stderr 写提示，stdout 偶尔也有 print；都接住交给前端显示。
    log = io.StringIO()
    try:
        with contextlib.redirect_stderr(log), contextlib.redirect_stdout(log):
            if action == "auto":
                score, final, path = codec.auto(text, int(payload.get("depth") or 3))
                result = {
                    "ok": True,
                    "result": final,
                    "score": round(float(score), 1),
                    "path": path,
                    "log": log.getvalue(),
                }
                if not path:
                    # auto 没找到可靠路径时不该只回一句「原样输出」。
                    # mojibake 这类乱码没有任何结构特征，structural_candidates
                    # 永远返回空；而它的判据是「损失 ≤2% 才认」，数据稍有损坏
                    # 就会被拒。这里兜底试一次最佳猜测，交给前端标成「不可全信」。
                    try:
                        guess, ratio, bad, enc = codec.mojibake_best(text)
                        # 三个条件都满足才算「疑似乱码」，否则宁可什么都不给：
                        #   · 长度 ≥6：两三个字的正常词很容易被凑出个「解」
                        #   · 损失 ≤50%
                        #   · 结果里替换符不超过三成（`你好` 会被猜成 `?A?n`）
                        if (guess and guess != text and len(text) >= 6
                                and 0 < ratio <= 0.5
                                and guess.count("\ufffd") <= len(guess) * 0.3):
                            result["partial"] = guess.replace("\ufffd", "?")
                            result["partial_note"] = (
                                "疑似乱码：损失 %.1f%%（%d 处缺失，假设 %s）"
                                % (ratio * 100, bad, enc))
                    except Exception:
                        pass
                return result

            if action in ("decode", "encode"):
                table = codec.DECODERS if action == "decode" else codec.ENCODERS
                fn = table.get(name)
                if not fn:
                    return {"ok": False,
                            "error": "这个方向不支持「%s」" % name,
                            "log": log.getvalue()}
                # mojibake 有两条附加通路（--best / --deep），别的解码器没有
                if action == "decode" and name == "mojibake":
                    return _run_mojibake(text, payload, log)
                out = _as_text(fn(text))
                return {"ok": True, "result": out, "log": log.getvalue()}

            if action == "brute":
                rows = codec.brute(text)
                cands = [{"score": round(float(s), 1), "name": n, "out": o}
                         for s, n, o in rows]
                return {"ok": True, "candidates": cands, "log": log.getvalue()}

            if action == "struct":
                # 只做结构识别，不解码 —— 让用户先看清「工具有没有认出来」
                names = codec.structural_candidates(text)
                cands = [{"name": n, "score": 0, "out": ""} for n in names]
                if not cands:
                    # 结构识别为空 ≠ 不是编码。mojibake 就是一堆看着正常的
                    # 汉字，没有任何可识别特征。这里补一次「最可能是什么」：
                    # 用损失率当线索，损失越低越像被误读的文本。
                    try:
                        guess, ratio, bad, enc = codec.mojibake_best(text)
                        if guess and guess != text and 0 < ratio <= 0.5:
                            cands.append({
                                "name": "mojibake（疑似）",
                                "score": round((1 - ratio) * 100, 1),
                                "out": "%s → %s，损失 %.1f%%"
                                       % (enc, "原编码", ratio * 100),
                            })
                    except Exception:
                        pass
                return {"ok": True, "candidates": cands, "log": log.getvalue()}

            return {"ok": False, "error": "未知操作：%s" % action}
    except Exception as e:
        # 解码器把「失败原因」放在异常消息里（ValueError("失败：…")），原样带出去
        return {"ok": False, "error": str(e) or type(e).__name__,
                "log": log.getvalue()}


# ---------------------------------------------------------------- HTTP 服务

class Handler(BaseHTTPRequestHandler):
    server_version = "puzzle-toolkit-ui"

    def log_message(self, fmt, *args):
        pass  # 别把每次请求都刷到终端，安静一点

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif path == "/api/list":
            try:
                body = {
                    "encodings": _encoding_names(),
                    # 用 getattr 而不是直接取属性：只更新了 ui.py、没更新
                    # ui_params.py 时，旧模块里没有这两个变量，直接取会
                    # AttributeError → 整个接口 500 → 前端下拉框全空，
                    # 用户看到的只是「没有选项」，完全猜不到原因。
                    "params": getattr(ui_params, "PARAMS", {}),
                    "tabs": getattr(ui_params, "TABS", []),
                }
                if not body["tabs"]:
                    body["warning"] = ("ui_params.py 是旧版（没有 TABS），"
                                       "它和 ui.py 必须一起更新")
                self._send(200, json.dumps(body, ensure_ascii=False))
            except Exception as e:
                self._send(200, json.dumps(
                    {"error": "加载功能列表失败：%s: %s" % (type(e).__name__, e)},
                    ensure_ascii=False))
        elif path == "/api/version":
            self._send(200, json.dumps({"ok": True}))
        else:
            self._send(404, json.dumps({"ok": False, "error": "not found"}))

    def do_POST(self):
        if self.path.split("?")[0] != "/api/run":
            self._send(404, json.dumps({"ok": False, "error": "not found"}))
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except Exception as e:
            self._send(400, json.dumps({"ok": False, "error": "请求解析失败：%s" % e}))
            return
        self._send(200, json.dumps(run_action(payload), ensure_ascii=False))


# ---------------------------------------------------------------- 前端页面

PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>puzzle-toolkit</title>
<style>
  :root {
    --bg:#1b1e24; --panel:#232830; --line:#333a45; --fg:#dfe4ea;
    --dim:#8b95a5; --accent:#4a9eff; --ok:#3dbd7d; --warn:#e5a24a; --err:#e56b6b;
  }
  * { box-sizing: border-box; }
  body {
    margin:0; background:var(--bg); color:var(--fg); height:100vh;
    display:flex; flex-direction:column;
    font:14px/1.55 "Microsoft YaHei UI","PingFang SC","Yu Gothic UI",
         "Noto Sans CJK SC",system-ui,sans-serif;
  }
  header { padding:10px 16px 0; border-bottom:1px solid var(--line); }
  h1 { margin:0 0 8px; font-size:15px; font-weight:600; letter-spacing:.4px; }
  h1 span { color:var(--dim); font-weight:400; font-size:12px; margin-left:8px; }
  nav { display:flex; gap:2px; }
  nav button {
    background:none; border:none; color:var(--dim); padding:7px 14px; cursor:pointer;
    font-size:13px; border-bottom:2px solid transparent; font-family:inherit;
  }
  nav button.active { color:var(--accent); border-bottom-color:var(--accent); }
  nav button:hover { color:var(--fg); }
  /* codec 专属按钮 / 其他选项卡的「执行」按钮互斥显示 */
  /* 只有「编码」页才显示那些按钮；其余选项卡一律隐藏。
     反过来写（默认显示、逐个 tab 关掉）会漏：加「进制」时就忘了补一行。 */
  .codec-only { display:none; }
  .not-codec { display:inline-flex; }
  body[data-tab="codec"] .codec-only { display:inline-flex; }
  body[data-tab="codec"] .not-codec { display:none; }
  /* 进制页是实时转换的，不需要「执行」；功能下拉也只有「转换」一项 */
  body[data-tab="num"] #btn-run,
  body[data-tab="num"] #enc { display:none; }

  .bar {
    display:flex; align-items:center; gap:8px; flex-wrap:wrap;
    padding:10px 16px; border-bottom:1px solid var(--line); background:var(--panel);
  }
  .sep { width:1px; height:20px; background:var(--line); margin:0 4px; }

  /* 参数区：内容由 ui_params.py 的声明动态生成 */
  .bar.sub {
    display:none; padding:6px 16px; background:#1f242b;
    font-size:12.5px; border-bottom:1px solid var(--line);
    align-items:center; gap:14px; flex-wrap:wrap;
  }
  .bar.sub.on { display:flex; }
  .pfield { display:flex; align-items:center; gap:6px; }
  .pfield .plabel { color:var(--dim); }
  .pfield .phint { color:#6d7683; font-size:11px; }
  .bar.sub select, .bar.sub input[type=text] {
    padding:3px 7px; font-size:12px; background:#171a20; color:var(--fg);
    border:1px solid var(--line); border-radius:4px;
  }
  .bar.sub input[type=number] {
    width:58px; padding:3px 6px; background:#171a20; color:var(--fg);
    border:1px solid var(--line); border-radius:4px; font-size:12px;
  }
  .bar.sub .suffix { color:var(--dim); margin-left:-3px; }
  button.act {
    background:#2d3540; color:var(--fg); border:1px solid var(--line);
    padding:6px 13px; border-radius:5px; cursor:pointer; font-size:13px;
    font-family:inherit;
  }
  button.act:hover { background:#37404d; }
  button.act.primary { background:#25507f; border-color:#2f6dad; }
  button.act.primary:hover { background:#2b5f96; }
  button.act:disabled { opacity:.4; cursor:default; }
  input[type=text], select, textarea {
    background:#171a20; color:var(--fg); border:1px solid var(--line);
    border-radius:5px; padding:6px 9px; font-family:inherit; font-size:13px;
  }
  input[type=text]:focus, textarea:focus, select:focus {
    outline:none; border-color:var(--accent);
  }
  #search { width:150px; }
  #enc { min-width:190px; font-family:ui-monospace,Consolas,monospace; }

  main { flex:1; display:flex; min-height:0; }
  .pane { flex:1; display:flex; flex-direction:column; min-width:0; padding:12px; }
  .pane + .pane { border-left:1px solid var(--line); }
  .pane label {
    font-size:12px; color:var(--dim); margin-bottom:6px;
    display:flex; align-items:center; gap:8px;
  }
  .pane label .tag { color:var(--accent); }
  textarea {
    flex:1; resize:none; line-height:1.5; min-height:0;
    font-family:ui-monospace,Consolas,"Courier New",monospace;
  }
  #output { background:#15181d; }

  /* ---- 进制面板：每行一个进制，值单独放在可复制的输入框里 ---- */
  #numout {
    display:none; flex:1; min-height:0; overflow:auto;
    border:1px solid var(--line); border-radius:5px; background:#15181d;
    padding:4px 2px;
  }
  body[data-tab="num"] #numout { display:block; }
  body[data-tab="num"] #output { display:none; }
  .numrow { display:flex; align-items:center; padding:0 4px; }
  .numrow .numbase {
    flex:0 0 54px; width:54px; text-align:right; color:var(--dim);
    font-size:12px; user-select:none;
    font-family:ui-monospace,Consolas,monospace;
  }
  .numrow.fav .numbase { color:var(--accent); font-weight:600; }
  .numrow .numval {
    flex:1; min-width:0; margin-left:6px; background:transparent;
    border:1px solid transparent; border-radius:3px; color:var(--fg);
    font-family:ui-monospace,Consolas,monospace; font-size:13px;
    padding:1px 6px;
  }
  .numrow .numval:hover { border-color:var(--line); }
  .numrow .numval:focus { outline:none; border-color:var(--accent); background:#1d222b; }

  .filrow { display:flex; align-items:center; gap:8px; margin-top:8px; font-size:12px; }
  .filrow input[type=file] { color:var(--dim); font-size:12px; max-width:210px; }
  .filrow .hint { color:var(--dim); }

  /* 频谱图预览：有图时替换掉文本框（图需要空间，一行字没必要留着） */
  #preview {
    display:none; flex:1; min-height:0; align-items:center;
    justify-content:center; overflow:auto; background:#0d0f13;
    border:1px solid var(--line); border-radius:5px;
  }
  #preview.on { display:flex; }
  #preview img {
    max-width:100%; max-height:100%; object-fit:contain; cursor:zoom-in;
  }
  #preview .hintbar {
    position:absolute; bottom:6px; right:10px; font-size:11px;
    color:var(--dim); background:rgba(13,15,19,.85); padding:2px 7px;
    border-radius:3px;
  }
  #preview .wrap { position:relative; display:flex; align-items:center;
                   justify-content:center; width:100%; height:100%; }
  body.img-on #output { display:none; }

  #cands { display:none; margin-bottom:8px; max-height:32%; overflow:auto;
           border:1px solid var(--line); border-radius:5px; }
  #cands.on { display:block; }
  .cand {
    display:flex; gap:10px; padding:5px 9px; cursor:pointer; font-size:12.5px;
    border-bottom:1px solid #2a303a;
    font-family:ui-monospace,Consolas,monospace; white-space:pre;
  }
  .cand:last-child { border-bottom:none; }
  .cand:hover { background:#2a303a; }
  .cand .sc { color:var(--warn); min-width:46px; text-align:right; }
  .cand .nm { color:var(--accent); min-width:78px; }
  .cand .tx { color:var(--fg); overflow:hidden; text-overflow:ellipsis; }

  footer {
    border-top:1px solid var(--line); padding:8px 16px; font-size:12px;
    color:var(--dim); height:168px; flex:0 0 168px; overflow:auto;
    white-space:pre-wrap; background:#15181d;
    font-family:ui-monospace,Consolas,monospace;
  }
  footer .err { color:var(--err); }
  footer .ok { color:var(--ok); }
  footer .warn { color:var(--warn); }
  .meta { color:var(--dim); font-size:12px; margin-left:8px; }
</style>
</head>
<body data-tab="codec">
<header>
  <h1>puzzle-toolkit <span>本地离线 · 只 import 现有脚本</span></h1>
  <nav id="tabs">
    <button class="active" data-tab="codec">编码</button>
    <button data-tab="classic">古典密码</button>
    <button data-tab="hashcrypto">哈希</button>
    <button data-tab="stego">隐写取证</button>
  </nav>
</header>

<div class="bar">
  <button class="act primary codec-only" id="btn-auto">自动识别</button>
  <button class="act codec-only" id="btn-struct" title="只看工具认不认得这是什么格式，不解码">识别格式</button>
  <span class="sep codec-only"></span>
  <input type="text" id="search" class="codec-only" placeholder="搜索编码…" autocomplete="off">
  <select id="enc"></select>
  <button class="act codec-only" id="btn-decode">解码</button>
  <button class="act codec-only" id="btn-encode">编码</button>
  <span class="sep codec-only"></span>
  <button class="act codec-only" id="btn-brute" title="每一种编码都试一遍">全试一遍</button>
  <button class="act primary not-codec" id="btn-run">执行</button>
</div>

<div class="bar sub" id="params"></div>

<main>
  <div class="pane">
    <label>输入 <span class="tag" id="inmeta"></span></label>
    <textarea id="input" spellcheck="false" placeholder="把密文粘到这里，或从下面选一个文件…"></textarea>
    <div class="filrow">
      <input type="file" id="file">
      <span class="hint" id="filehint">读取文件时会替换上面的内容</span>
    </div>
  </div>
  <div class="pane">
    <label>结果 <span class="tag" id="outmeta"></span></label>
    <div id="cands"></div>
    <textarea id="output" readonly spellcheck="false"
              placeholder="结果显示在这里。点候选里的任意一行可以把它填到输入框。"></textarea>
    <div id="numout"></div>
    <div id="preview"></div>
  </div>
</main>

<footer id="log">就绪。选中输入框后 Ctrl+Enter 直接自动识别。</footer>

<script>
const $ = (id) => document.getElementById(id);
const input = $("input"), output = $("output"), encSel = $("enc"),
      search = $("search"), cands = $("cands"), log = $("log");

let ENCODINGS = [], PARAMSPEC = {}, TABS = [], currentTab = "codec";

function say(msg, kind) {
  log.className = "";
  log.innerHTML = "";
  const span = document.createElement("span");
  if (kind) span.className = kind;
  span.textContent = msg;
  log.appendChild(span);
}

function setBusy(b) {
  for (const id of ["btn-auto","btn-decode","btn-encode","btn-brute","btn-struct"])
    $(id).disabled = b;
}

async function loadList() {
  try {
    const r = await fetch("/api/list");
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    if (data.error) throw new Error(data.error);
    ENCODINGS = data.encodings || [];
    PARAMSPEC = data.params || {};
    TABS = data.tabs || [];
    if (!TABS.length)
      throw new Error(data.warning || "ui_params.py 是本目录下的旧版本");
    renderTabs();
    fillFuncs();
  } catch (e) {
    say("加载功能列表失败：" + e.message +
        "\n\n界面需要两个文件同时存在且都是最新版：ui.py 和 ui_params.py。" +
        "\n只更新其中一个会出现「下拉框是空的、点了没反应」这种症状。", "err");
  }
}

function tabDef() {
  return TABS.find(t => t.id === currentTab) || { id: "codec", kind: "encoding" };
}

// 当前选项卡的功能列表：codec 用编码表，其余用脚本子命令
function funcList() {
  const t = tabDef();
  if (t.kind === "encoding") return ENCODINGS;
  return (t.actions || []).map(a => ({ name: a.name, label: a.label, aliases: [] }));
}

// 参数表的键：codec 直接用编码名，其余用 "选项卡/功能"
function paramKey() {
  return tabDef().kind === "encoding"
    ? encSel.value
    : currentTab + "/" + encSel.value;
}

function fillFuncs() {
  const t = tabDef();
  // 搜索框只属于「编码」页。它虽然被 CSS 隐藏，value 却一直留着——在编码页
  // 搜过 "atbash" 再切到古典密码，下面的过滤会把下拉吃成只剩 atbash；
  // 哈希页没有匹配项，干脆空掉。所以非编码页一律忽略它。
  const q = (t.kind === "encoding") ? search.value.trim().toLowerCase() : "";
  const items = funcList().filter(e =>
    !q || e.name.toLowerCase().includes(q) ||
    (e.label || "").toLowerCase().includes(q) ||
    (e.aliases || []).some(a => a.toLowerCase().includes(q)));
  const prev = encSel.value;
  encSel.innerHTML = "";
  for (const e of items) {
    const o = document.createElement("option");
    o.value = e.name;                       // 发给后端的是真实名字
    const mark = (e.dec && e.enc) ? "  ↕" : (e.dec ? "  ↓" : "  ↑");
    o.textContent = (e.label || e.name) + mark;
    if (e.aliases && e.aliases.length)
      o.title = "别名：" + e.aliases.join("、");
    encSel.appendChild(o);
  }
  if (prev && items.some(e => e.name === prev)) encSel.value = prev;
  search.style.display = (t.kind === "encoding") ? "" : "none";
  renderParams();
}

function updateMeta() {
  const t = input.value;
  $("inmeta").textContent = t ? `${[...t].length} 字符 / ${new TextEncoder().encode(t).length} 字节` : "";
}

async function call(payload) {
  setBusy(true);
  say("处理中…");
  try {
    const r = await fetch("/api/run", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    return await r.json();
  } catch (e) {
    return { ok: false, error: "请求失败：" + e };
  } finally {
    setBusy(false);
  }
}

function showLog(res) {
  const parts = [];
  if (res.log && res.log.trim()) parts.push(res.log.trim());
  if (res.ok && res.path && res.path.length)
    parts.push("路径：" + res.path.join(" → ") + (res.score !== undefined ? `　得分 ${res.score}` : ""));
  if (parts.length) say(parts.join("\n"));
}

// 图片预览：stego 的 spec 会产出 PNG，后端转成 base64 一起返回
function showImage(b64, name) {
  const box = $("preview");
  box.innerHTML = "";
  const on = !!b64;
  box.classList.toggle("on", on);
  document.body.classList.toggle("img-on", on);
  if (!on) return;

  const wrap = document.createElement("div");
  wrap.className = "wrap";
  const img = document.createElement("img");
  img.src = "data:image/png;base64," + b64;
  img.alt = name || "频谱图";
  img.onclick = () => {                    // 点一下开新标签看原尺寸
    const w = window.open();
    if (w) w.document.write('<title>' + (name || "频谱图") +
      '</title><body style="margin:0;background:#111"><img src="' + img.src +
      '" style="max-width:100%">');
  };
  wrap.appendChild(img);
  const bar = document.createElement("div");
  bar.className = "hintbar";
  bar.textContent = (name || "spectrum.png") + "　点击图片可放大";
  wrap.appendChild(bar);
  box.appendChild(wrap);
}

function renderCandidates(list) {
  cands.innerHTML = "";
  if (!list || !list.length) { cands.classList.remove("on"); return; }
  for (const c of list) {
    const row = document.createElement("div");
    row.className = "cand";
    if (c.score) {
      const sc = document.createElement("span");
      sc.className = "sc"; sc.textContent = c.score.toFixed(1);
      row.appendChild(sc);
    }
    if (c.name) {
      const nm = document.createElement("span");
      nm.className = "nm"; nm.textContent = c.name;
      row.appendChild(nm);
    }
    if (c.out) {
      const tx = document.createElement("span");
      tx.className = "tx"; tx.textContent = c.out.replace(/\n/g, "⏎");
      row.appendChild(tx);
    }
    row.onclick = () => {
      if (c.out) { input.value = c.out; updateMeta(); }
    };
    cands.appendChild(row);
  }
  cands.classList.add("on");
}

async function doAuto() {
  showImage(null);
  const res = await call({ action: "auto", text: input.value });
  renderCandidates([]);
  if (!res.ok) { output.value = ""; say("失败：" + res.error, "err"); return; }
  if (res.result !== input.value) {
    output.value = res.result;
    $("outmeta").textContent = "";
    showLog(res);
    return;
  }
  // 没解出来。如果后端兜底给了「疑似乱码」的最佳猜测，别让结果区空着，
  // 但一定要标清楚这不是可信结果。
  if (res.partial) {
    output.value = res.partial;
    $("outmeta").textContent = "疑似";
    say((res.partial_note || "自动识别把握不大") +
        "\n? 处是丢失的字节。" +
        "\n建议使用 mojibake 模式的「最佳猜测」。", "warn");
    return;
  }
  output.value = "";
  $("outmeta").textContent = "";
  say("没有可靠的编码路径。可试试「全试一遍」，或用下拉框手动指定。", "warn");
}

async function doStruct() {
  showImage(null);
  const res = await call({ action: "struct", text: input.value });
  renderCandidates([]);
  if (!res.ok) { say("失败：" + res.error, "err"); return; }
  const list = (res.candidates || []).filter(c => c.name);
  if (!list.length) {
    say("没有认出任何已知格式 —— 它可能不是编码，或者是这里没覆盖的格式。", "warn");
    return;
  }
  // 结构匹配到的只写名字；兜底猜出来的那条带「损失 X%」说明
  const lines = list.map(c => c.out ? `${c.name}　${c.out}` : c.name);
  const guessed = list.some(c => c.out);
  say("结构识别结果：\n  " + lines.join("\n  "), guessed ? "warn" : "");
}

// ---- 参数区：完全由 ui_params.py 的声明驱动，这里不认识任何具体功能 ----
function renderParams() {
  const box = $("params");
  const spec = PARAMSPEC[paramKey()] || [];
  box.innerHTML = "";
  box.classList.toggle("on", spec.length > 0);
  if (!spec.length) return;
  for (const p of spec) {
    const field = document.createElement("label");
    field.className = "pfield";
    field.dataset.key = p.key;
    if (p.show_if) field.dataset.showif = JSON.stringify(p.show_if);

    const lb = document.createElement("span");
    lb.className = "plabel";
    lb.textContent = p.label;
    field.appendChild(lb);

    let ctl;
    if (p.type === "choice") {
      ctl = document.createElement("select");
      for (const c of p.choices) {
        const o = document.createElement("option");
        o.value = c[0]; o.textContent = c[1];
        ctl.appendChild(o);
      }
      ctl.value = (p.default !== undefined) ? p.default : p.choices[0][0];
    } else if (p.type === "int") {
      ctl = document.createElement("input");
      ctl.type = "number";
      // 没有 default 就是「留空 = 自动」。以前这里硬填 0，于是每个数字化可选参数
      // 都带着 0 发出去：grid 的阈值变 0（全部格子判成一类）、凯撒位移变 0
      // （本该全爆破却只解一种）、仿射 a/b 变 0。
      ctl.value = (p.default !== undefined) ? p.default : "";
      if (p.min !== undefined) ctl.min = p.min;
      if (p.max !== undefined) ctl.max = p.max;
    } else {
      ctl = document.createElement("input");
      ctl.type = "text";
      ctl.placeholder = p.placeholder || "";
      if (p.default !== undefined) ctl.value = p.default;
    }
    ctl.id = "p_" + p.key;
    ctl.addEventListener("change", refreshParamVis);
    ctl.addEventListener("input", refreshParamVis);
    field.appendChild(ctl);

    if (p.suffix) {
      const s = document.createElement("span");
      s.className = "suffix"; s.textContent = p.suffix;
      field.appendChild(s);
    }
    if (p.hint) {
      const h = document.createElement("span");
      h.className = "phint"; h.textContent = p.hint;
      field.appendChild(h);
    }
    box.appendChild(field);
  }
  refreshParamVis();
}

function refreshParamVis() {
  for (const el of $("params").querySelectorAll(".pfield")) {
    const cond = el.dataset.showif;
    if (!cond) continue;
    const want = JSON.parse(cond);
    let ok = true;
    for (const k in want) {
      const ctl = $("p_" + k);
      if (!ctl || ctl.value !== want[k]) ok = false;
    }
    el.style.display = ok ? "" : "none";
  }
}

function paramValues() {
  const out = {};
  for (const p of (PARAMSPEC[paramKey()] || [])) {
    const ctl = $("p_" + p.key);
    if (!ctl) continue;
    if (p.type === "int") {
      const n = parseInt(ctl.value, 10);
      if (!isNaN(n)) out[p.key] = n;
    } else {
      const v = (ctl.value || "").trim();
      if (v) out[p.key] = v;
    }
  }
  return out;
}

async function doDecodeOrEncode(dir) {
  showImage(null);
  const payload = { action: dir, name: encSel.value, text: input.value };
  const pv = paramValues();
  // mode 是界面上的合成概念，拆回后端认识的 best / deep
  if (pv.mode === "best") payload.best = true;
  else if (pv.mode === "deep") payload.deep = pv.deep;
  delete pv.mode;
  Object.assign(payload, pv);

  const res = await call(payload);
  renderCandidates([]);
  if (!res.ok) {
    if (res.partial) {
      // 解不动，但解码器在错误消息里其实给了最佳猜测：填进结果区。
      output.value = res.partial;
      $("outmeta").textContent = "最佳猜测";
      say(res.error, "warn");
    } else {
      output.value = "";
      $("outmeta").textContent = "";
      say("失败：" + res.error, "err");
    }
    if (res.log && res.log.trim()) log.textContent += "\n" + res.log.trim();
    return;
  }
  output.value = res.result;
  $("outmeta").textContent = "";
  showLog(res);
  if (!res.log || !res.log.trim())
    say((dir === "decode" ? "解码" : "编码") + "完成：" + (encSel.selectedOptions[0]?.textContent || encSel.value), "ok");
}

async function doBrute() {
  showImage(null);
  const res = await call({ action: "brute", text: input.value });
  if (!res.ok) { say("失败：" + res.error, "err"); return; }
  const list = res.candidates || [];
  if (!list.length) { renderCandidates([]); say("没有一种编码能给出可读结果。", "warn"); return; }
  renderCandidates(list);
  output.value = list[0].out;
  say(`试了 ${list.length} 种，按可读性排序。点候选行可填入输入框。`);
}

// ---- 事件
function switchTab(id) {
  currentTab = id;
  document.body.dataset.tab = id;
  for (const b of document.querySelectorAll("#tabs button"))
    b.classList.toggle("active", b.dataset.tab === id);
  encSel.innerHTML = "";          // 强制重新选第一项，避免残留上一个选项卡的值
  if (tabDef().kind !== "encoding") search.value = "";   // 搜索词别跨选项卡残留
  fillFuncs();
  renderCandidates([]);
  const needFile = tabDef().input === "file";
  input.disabled = needFile;
  input.placeholder = needFile
    ? "这个选项卡处理的是文件，请用下面的「选择文件」。\n（文本框禁用是因为二进制数据当文本读会被破坏）"
    : "把密文粘到这里，或从下面选一个文件…";
  say("已切到「" + (tabDef().label || id) + "」" +
      (needFile ? "　→ 请先选择一个文件" : ""), needFile ? "warn" : "");
  if (id === "num") doNum();
}

// classic / hashcrypto / stego 的执行入口：参数由参数表收集，原样交给后端
async function doRun() {
  if (currentTab === "num") return doNum();
  const payload = {
    tab: currentTab,
    action: encSel.value,
    text: input.value,
    params: paramValues(),
  };
  if (currentTab === "stego") {
    payload.file_b64 = FILE_B64;
    payload.filename = FILE_NAME;
  }
  const res = await call(payload);
  renderCandidates([]);
  output.value = res.result || "";
  $("outmeta").textContent = "";
  showImage(res.image_b64 || null, res.image_name);   // 非 spec 时这会把图清掉
  // 脚本的分析走 stderr、被后端收进 res.log，显示在底部提示条，
  // 结果框里只留结果。
  const notes = (res.log || "").trim();
  if (!res.ok) {
    say(notes ? (res.error || "执行出错") + "\n\n" + notes : (res.error || "执行出错"), "err");
  } else if (notes) {
    say(notes);
  } else {
    say((encSel.selectedOptions[0]?.textContent || encSel.value) + "　完成", "ok");
  }
}

// 进制面板：一个数 → 2..36 全部写法。每行一个只读输入框，
// 点一下全选、Ctrl+C 就能只复制那一项。
let numTimer = null;
async function doNum() {
  const box = $("numout");
  if (!input.value.trim()) {
    box.innerHTML = "";
    $("outmeta").textContent = "";
    say("输入一个数，下面会列出它 2..36 的全部写法；" +
        "原文不是十进制就在上方「按几进制读」里选", "");
    return;
  }
  const res = await call({
    tab: "num", action: "convert", text: input.value, params: paramValues(),
  });
  box.innerHTML = "";
  $("outmeta").textContent = "";
  if (!res.ok) { say(res.error || "转换失败", "err"); return; }
  const fav = { 2: "bin", 8: "oct", 10: "dec", 16: "hex" };
  for (const [b, s] of res.pairs) {
    const row = document.createElement("div");
    row.className = "numrow" + (fav[b] ? " fav" : "");
    const lab = document.createElement("span");
    lab.className = "numbase";
    lab.textContent = fav[b] || ("b" + b);
    const v = document.createElement("input");
    v.className = "numval";
    v.readOnly = true;
    v.value = s;
    v.title = "点一下全选，Ctrl+C 只复制这一项";
    v.addEventListener("click", () => v.select());
    row.appendChild(lab);
    row.appendChild(v);
    box.appendChild(row);
  }
  if (res.note) say(res.note, "warn");
  else say("「" + res.token + "」按 " + res.src + " 进制读　→　2..36 共 35 行", "ok");
}

// 选项卡按钮从 TABS 生成，不写死在 HTML 里 —— 写死过一次，结果后端加了
// 「进制」tab、/api/list 也返回了，界面却还是四个按钮（nav 里没加）。
function renderTabs() {
  const nav = $("tabs");
  nav.innerHTML = "";
  for (const t of TABS) {
    const b = document.createElement("button");
    b.dataset.tab = t.id;
    b.textContent = t.label || t.id;
    b.onclick = () => switchTab(t.id);
    nav.appendChild(b);
  }
}

$("btn-auto").onclick = doAuto;
$("btn-struct").onclick = doStruct;
$("btn-brute").onclick = doBrute;
$("btn-decode").onclick = () => doDecodeOrEncode("decode");
$("btn-encode").onclick = () => doDecodeOrEncode("encode");
$("btn-run").onclick = doRun;

// 参数控件是每次切换功能时重建的，所以事件挂在容器上做委托。
// 进制页改「按几进制读」后必须立刻重算——之前只绑了输入框的 input 事件，
// 改下拉没反应，得在输入框里敲一下才会刷。
$("params").addEventListener("change", () => {
  if (currentTab === "num") doNum();
});

search.oninput = fillFuncs;
encSel.onchange = renderParams;

input.addEventListener("input", updateMeta);
input.addEventListener("input", () => {
  if (currentTab !== "num") return;
  clearTimeout(numTimer);
  numTimer = setTimeout(doNum, 300);
});
input.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); doAuto(); }
});

// stego 要原始字节，文本类选项卡仍按文本读；两边都存一份 base64 备用
let FILE_B64 = null, FILE_NAME = "";

function b64FromBuffer(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  const CHUNK = 0x8000;                 // 分块，免得大文件把栈撑爆
  for (let i = 0; i < bytes.length; i += CHUNK)
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  return btoa(bin);
}

$("file").onchange = async (e) => {
  const f = e.target.files[0];
  if (!f) { FILE_B64 = null; FILE_NAME = ""; return; }
  FILE_NAME = f.name;
  try {
    FILE_B64 = b64FromBuffer(await f.arrayBuffer());
    $("filehint").textContent = "已读入 " + f.name + "（" + f.size + " 字节）";
    if (tabDef().input !== "file") {     // 文本类选项卡顺便填进输入框
      input.value = await f.text();
      updateMeta();
    }
  } catch (err) {
    say("读文件失败：" + err, "err");
  }
};

document.body.dataset.tab = "codec";
loadList();
updateMeta();
input.focus();
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="puzzle-toolkit 的本地图形界面")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1",
                    help="默认只监听本机；想让手机访问用 0.0.0.0")
    ap.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = ap.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = "http://%s:%d/" % ("127.0.0.1" if args.host == "0.0.0.0" else args.host,
                             args.port)
    print("puzzle-toolkit UI 已启动：%s" % url)
    print("按 Ctrl+C 停止")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
