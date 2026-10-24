# puzzle-toolkit

解谜 / CTF 用的离线解码工具箱。四个脚本，纯 Python 标准库，无第三方依赖。

## 快速开始

```bash
curl -O https://raw.githubusercontent.com/Seve0r/puzzle-toolkit/main/codec.py
python3 codec.py auto 'S1VWRVIgTEFOR1VBR0U='
```

单个脚本就能跑。想要全部四个 + 内置词表，用下面的完整安装。

> Windows PowerShell 里 `curl` 是 `Invoke-WebRequest` 的别名，语法不同，请写 `curl.exe`。

## 安装

### Linux / macOS

```bash
git clone https://github.com/Seve0r/puzzle-toolkit.git ~/tools/puzzle-toolkit
```

加到 `~/.bashrc`：

```bash
D=~/tools/puzzle-toolkit
alias codec="python3 $D/codec.py"
alias classic="python3 $D/classic.py"
alias hc="python3 $D/hashcrypto.py"
alias stego="python3 $D/stego.py"
```

### Windows

PowerShell：

```powershell
git clone https://github.com/Seve0r/puzzle-toolkit.git "$HOME\tools\puzzle-toolkit"
```

在脚本所在目录为每个脚本建一个 `.cmd`，例如 `codec.cmd`：

```bat
@echo off
py "%~dp0codec.py" %*
```

然后把该目录加入用户环境变量 `Path`，**重新打开终端**。
若 `py` 命令不存在，把上面的 `py` 换成 `python`。

建议先执行一次，避免中文输出报 GBK 错：

```powershell
setx PYTHONUTF8 1
```

### 不装也行

任何系统上这样都能直接跑，不需要配 PATH：

```bash
python3 ~/tools/puzzle-toolkit/codec.py auto 'S1VWRVIgTEFOR1VBR0U='
```

```powershell
py "$HOME\tools\puzzle-toolkit\codec.py" auto 'S1VWRVIgTEFOR1VBR0U='
```

## 先跑哪个

手上有东西但不确定是什么，先查这张表：

| 看到什么 | 跑什么 |
|---|---|
| Base64 长相（`A-Za-z0-9+/=`） | `codec auto` |
| 纯 `0` 和 `1` | `codec dec bin` |
| `%XX` / `&#x..` / `\u..` | `codec auto` |
| 大量 `0000` 的 8 位分组 | `codec auto`（UTF-32） |
| 点划序列 | `codec auto`（摩斯） |
| 像英语但读不通 | `classic auto` |
| 32/40/64 位 hex | `hc identify` → `hc crack` |
| 图片 / 音频 / 压缩包 | `stego binwalk` |
| 疑似图片藏东西 | `stego lsbscan` |
| 音频 | `stego spec` |

两点补充：二进制串要整段一起喂，别按行切；`stego lsbscan` 比 `lsb` 更彻底。

每个脚本 `-h` 看完整参数，`docs/` 下有各脚本的详细说明。

## 关于词表

`classic.py` 的单表替换破解、`hashcrypto.py` 的字典爆破需要英语词表。按顺序找第一个可用的：

1. 环境变量 `PUZZLE_WORDLIST` 指定的文件
2. 仓库内 `data/words.txt`（约 1500 个常用词，随仓库分发）
3. 系统词典 `/usr/share/dict/words` 等（Linux / macOS）

Windows 上不存在 `/usr/share/dict`，会直接用 `data/words.txt`，功能正常。
如果一份词表都找不到，程序会在 stderr 明确提示"评分已退化为 bigram"，
不会静默降级。

想要更强的爆破能力，指向更大的字典即可：

```bash
export PUZZLE_WORDLIST=/path/to/rockyou.txt
```

Debian / Ubuntu 默认不装系统词典，需要的话：

```bash
sudo apt install wamerican
```

## 目录结构

```
puzzle-toolkit/
  codec.py        编码识别与解码
  classic.py      古典密码
  hashcrypto.py   哈希与现代密码
  stego.py        文件隐写
  data/words.txt  内置英语词表（约 1500 常用词）
  docs/           各脚本的详细说明
```

## 依赖

只需要 Python 3.8+。

两个功能依赖外部命令，缺了不影响其余部分：

- `stego.py qr` 需要 `zbarimg`（`apt install zbar-tools`）
- `stego.py spec` 需要 `ffmpeg`
