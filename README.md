# puzzle-toolkit

解谜时自己用的离线工具箱。四个脚本 + 一个图形界面，纯 Python 标准库，
无第三方依赖。主要是我解 ARG 谜题时用；刚开始学这些，所以顺手写了一些操作说明。

## 两种用法

**命令行**（下面所有文档讲的方式），以及**图形界面**：

```bash
python3 ui.py            # 起本地服务并自动打开浏览器
```

Windows 上直接双击 `启动界面.bat`（不弹黑框也行，用 `pythonw`）。
手机想用就 `python3 ui.py --host 0.0.0.0`，同一个局域网内访问
`http://<这台机器的IP>:8765/` —— 但**校园网/公共网络别这么开**，端口会暴露。

界面四个选项卡，就是四个脚本的完整封装：

| 选项卡 | 输入 | 能做什么 |
|---|---|---|
| 编码 | 文本 | 37 种编码的解码/编码、自动识别、识别格式、全试一遍 |
| 古典密码 | 文本 | 凯撒 / 维吉尼亚 / 仿射 / 培根 / 栅栏 / 列置换 / Playfair / ADFGX / 键盘 / T9 等 16 个 |
| 哈希 | 文本 | 识别、字典爆破、**按格式穷举**、XOR、AES、RC4、RSA、JWT |
| 隐写取证 | **文件** | binwalk / LSB / strings / exif / 二维码 / 频谱图 等 13 个 |

界面和命令行**用的是同一份代码** —— 它只是 `import` 后调用，所以修了脚本的 bug，
界面会自动跟着变，不存在两边不同步。

三个使用上的注意：

- **`ui.py` 和 `ui_params.py` 必须一起更新**。后者是选项卡与参数表，只换前者会
  导致下拉框空白、按钮点了没反应（新版会明确提示是哪个文件旧了）。
- **隐写取证必须选文件**，输入框会被禁用 —— 那些命令要的是原始字节，
  把 PNG / MP3 当文本读会直接损坏数据。
- **频谱图会直接显示在结果区**（点击可放大），不用再去临时目录里翻文件。

## 快速开始

```bash
git clone https://github.com/Seve0r/puzzle-toolkit.git
cd puzzle-toolkit
python3 codec.py auto 'S1VWRVIgTEFOR1VBR0U='
```

## 安装

### Linux / macOS

clone 到任意位置，下面假设 `~/tools/puzzle-toolkit`（换成你自己习惯的路径也行）：

```bash
git clone https://github.com/Seve0r/puzzle-toolkit.git ~/tools/puzzle-toolkit
```

然后用 alias 把它们变成命令。**两步都要先确认，直接用抄来的会失效**：

**① 你用的是哪个 shell？**

```bash
echo $SHELL
```

| 输出 | 改这个文件 |
|---|---|
| `/bin/bash` | `~/.bashrc` |
| `/bin/zsh` | `~/.zshrc`（macOS 默认、很多 Linux 也是） |

**② 仓库实际 clone 在哪？** 下面这个 `D` 必须是你自己的真实路径——
写错的话 alias 会指向一个不存在的文件，命令报 `No such file or directory`：

```bash
D=~/tools/puzzle-toolkit      # ← 改成你实际 clone 的位置
alias codec="python3 $D/codec.py"
alias classic="python3 $D/classic.py"
alias hc="python3 $D/hashcrypto.py"
alias stego="python3 $D/stego.py"
```

验证一下 `D` 对不对：

```bash
ls $D/codec.py     # 能列出来才对
```

改完 `source ~/.zshrc`（或 `~/.bashrc`），或者重开终端生效。

### Windows

仓库是公开的，克隆不需要任何认证。PowerShell：

```powershell
git clone https://github.com/Seve0r/puzzle-toolkit.git "$HOME\tools\puzzle-toolkit"
```

没装 Git 也行：网页上点 **Code → Download ZIP**，解压到 `%USERPROFILE%\tools\puzzle-toolkit`。
**注意别漏掉 `data/words.txt`**，少了它单表替换破解会降级。

只有想往回 push 时才需要认证：`ssh-keygen -t ed25519` 生成密钥，把 `id_ed25519.pub`
的内容贴到 https://github.com/settings/keys ；或者用 GitHub Desktop 登录。

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

## 怎么喂数据

**优先用 `-f` 从文件读，不要把密文直接塞进命令行。**

```bash
python3 codec.py auto -f cipher.txt
python3 codec.py dec bin -f bits.txt
python3 codec.py enc hex -f picture.png
```

四种情况下 `-f` 是唯一靠谱的方式：

- **多行密文**：cmd 会把粘贴内容里的换行当成命令分隔符，直接执行下一行
- **超长密文**：cmd 单条命令上限约 8191 字符，超出会被**静默截断**
- **含特殊字符**：`$`、`&`、`"` 在 PowerShell 里会被解释掉
- **二进制文件**：只有 `-f` 能拿到原始字节，否则会被 UTF-8 替换成 U+FFFD

生成文件最快的办法：记事本粘贴 → 另存为 → 编码选 **UTF-8**。

三条容易踩的用错：

1. **多行二进制要整段喂**。按行切会切断字符的字节边界，每行都解出半个字。
2. **混合编码不能自动分段**。一份文件里有 base64 + hex + 二进制时，`auto` 只套用一种解码器，得先手工切分、每次喂一段。
3. **二进制文件（图片 / 音频 / 压缩包）用 `stego.py`**，`codec.py` 面向文本。

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
| 中文正常但读不通（`浜哄彧`） | `codec dec mojibake`，解完还乱就加 `--deep` |
| 一堆生僻汉字但不像中文（`孨偼堦惗`） | `codec dec mojibake`（GBK 编的日文被当 GBK 读） |
| 一份文件里混着几种编码 | 先手工切分，每次喂一段 |
| 32/40/64 位 hex | `hc identify` → `hc crack`（字典）或 `hc mask`（纯数字/已知格式） |
| 图片 / 音频 / 压缩包 | `stego binwalk` |
| 疑似图片藏东西 | `stego lsbscan` |
| 音频 | `stego spec` |

两点补充：二进制串要整段一起喂，别按行切；`stego lsbscan` 比 `lsb` 更彻底。

每个脚本 `-h` 看完整参数，`docs/` 下有各脚本的详细说明。

## 全部命令

### codec.py —— 编码识别与解码

| 命令 | 说明 |
|---|---|
| `codec auto <文本>` | 自动识别编码并递归剥皮（默认 3 层） |
| `codec brute <文本>` | 每种编码都试一遍，列出所有可读结果 |
| `codec dec <编码名> <文本>` | 用指定编码解码 |
| `codec enc <编码名> <文本>` | 用指定编码编码 |
| `codec list` | 列出全部支持的编码名 |
| `codec dec mojibake <文本>` | 还原乱码（`浜哄彧` → `人只`）。UTF-8 被当 GBK 读、中日韩编码互相误读都认 |
| `codec dec mojibake --deep [N]` | 多层乱码反复还原，直到正常文字占比 ≥ N%（默认 50） |
| `codec dec mojibake --best <文本>` | 数据本身残缺时强制输出最佳猜测，缺失处标 `?`，并给出损失率 |
| `codec dec mojibake --from A --to B` | 显式指定乱码的编码对，不猜（如 `--from gbk --to shift_jis`） |
| `codec grid <文本>` | 切矩阵枚举读法（行优先/列优先/蛇形/反转），可加 `--rows` `--cols` `--width` |
| `codec blocks <文本>` | 定长块按进制转字节，如 `blocks -w 2 -r 36`（两位 base36 = 一字节） |

支持的编码有四十多种（base16/32/58/62/64/85/91、hex、二进制、URL、HTML 实体、
Unicode 转义、摩斯、和文摩斯、盲文、gzip/zlib/bz2、UTF-16/32、GBK、punycode、mojibake…），
完整列表用 `codec list`。

### classic.py —— 古典密码

| 命令 | 说明 |
|---|---|
| `classic auto <文本>` | 全部手法跑一遍，按英文契合度排序 |
| `classic caesar [--key N] <文本>` | 凯撒；不给 key 就 26 种全爆破 |
| `classic vigenere --key K <文本>` | 维吉尼亚，`--enc` 加密 |
| `classic vigcrack <文本>` | 维吉尼亚无密钥破解（IC 定长 + 逐列频率） |
| `classic affine [--a N --b N] <文本>` | 仿射；不给参数就 312 种全爆破 |
| `classic sub <文本>` | 单表替换爬山法破解（需 ≥300 字母才可靠） |
| `classic bacon [--old] <文本>` | 培根密码，也吃大小写隐写 |
| `classic railfence [--rails N] <文本>` | 栅栏；不给栏数就全爆破 |
| `classic columnar [--key K] <文本>` | 列置换；不给 key 就按长度爆破 |
| `classic atbash <文本>` | Atbash（反字母表） |
| `classic a1z26 [--dec] <文本>` | A1Z26（1–26 ↔ a–z） |
| `classic polybius [--dec] <文本>` | 波利比奥斯方阵（I/J 合并） |
| `classic playfair --key K <文本>` | 普莱菲尔方阵，`--enc` 加密，`--clean` 去掉填充 x |
| `classic adfgx --key K [--trans K] <文本>` | ADFGX 方阵 |
| `classic keyboard [--layout qwerty\|dvorak\|azerty] <文本>` | 键盘错位还原 |
| `classic t9 <数字>` | 手机九宫格，列出所有可能 |

### hashcrypto.py —— 哈希与现代密码

| 命令 | 说明 |
|---|---|
| `hc identify <哈希>` | 猜测哈希类型（长度 / 字符集 / 前缀） |
| `hc hash <算法> <文本>` | 计算哈希 |
| `hc crack <哈希> [--algo A] [--wordlist F] [--rules]` | 字典爆破，不给 algo 就自动识别 |
| `hc mask <哈希> --len 8 --charset digits` | **按格式穷举**（掩码爆破），多进程；`--mask "?d?d?d?d"` 写法同 hashcat |
| `hc xor <数据> [--key HEX \| --key-str TEXT]` | 单字节全试 / 指定 key 异或 / 多字节自动 |
| `hc repeat-xor <文件>` | 检测重复密钥 XOR 并还原密钥 |
| `hc aes --key HEX [--iv HEX] [--mode cbc\|ecb\|ctr\|gcm] <数据>` | AES 解密，`--enc` 加密 |
| `hc rc4 --key TEXT <数据>` | RC4 |
| `hc rsa --n N --e E [--c C] [--d D]` | RSA 解密与常见攻击 |
| `hc jwt <token> [--crack]` | 解析 JWT；按 `alg` 爆破 HS256/384/512 密钥 |
| `hc list` | 列出识别的哈希类型 |

### stego.py —— 文件隐写取证

| 命令 | 说明 |
|---|---|
| `stego binwalk <文件>` | 扫描内嵌文件特征 |
| `stego tail <文件>` | 检测文件尾附加数据（IEND / EOI / GIF trailer 之后） |
| `stego strings <文件> [-n 6]` | 可打印字符串，标出可疑项（flag / URL / base64 / 长 hex） |
| `stego lsb <图片>` | 逐通道 LSB 提取 |
| `stego lsbscan <图片>` | 更彻底：1~3 位、6 种通道组合 |
| `stego exif <图片>` | 读元数据（EXIF / PNG 文本块 / 注释） |
| `stego pngchunks <png>` | 列出 PNG 每个块，标出可疑块 |
| `stego zipinfo <zip>` | 不依赖 unzip：列条目、注释、伪加密标记 |
| `stego unzip <zip> [--out 目录]` | 解压到目录（只支持 store/deflate，加密条目跳过，带路径越界防护） |
| `stego hexdump <文件> [-l N]` | 十六进制查看 |
| `stego qr <图片> [--all]` | 识别二维码/条形码，`--all` 会放大 2×/4× 重试 |
| `stego spec <音频> [--out 图.png]` | 生成频谱图（看隐藏的摩斯/文字） |
| `stego meta <文件>` | 文件类型 + 尺寸 + 熵 |

### 通用选项

| 选项 | 适用 | 说明 |
|---|---|---|
| `-f, --file <路径>` | codec / classic / hc | 从文件读输入，二进制安全。多行/超长/带特殊字符时**必须用这个**。`stego` 的文件直接作位置参数，不需要 `-f` |
| `-q, --quiet` | 全部 | 只输出结果，不要解释 |
| `--depth N` | `codec auto` | 递归剥皮层数，默认 3 |
| `--best` | `codec dec mojibake` | 数据本身残缺时，强制输出最佳猜测，缺失处标 `?` |
| `--from A --to B` | `codec dec mojibake` | 显式指定乱码的编码对（源 → 目标），跳过猜测 |
| `--katakana` | `codec dec wabun` | 输出片假名（默认平假名） |
| `--enc` | `classic` / `hc` | 编码方向（默认解码） |
| `-h, --help` | 全部 | 看完整参数 |

### ui.py —— 图形界面

浏览器版的界面，封装了上面四个脚本。不是命令，是个服务：

| 命令 / 选项 | 说明 |
|---|---|
| `python3 ui.py` | 起服务并自动打开浏览器（默认 `http://127.0.0.1:8765/`） |
| `--port N` | 换端口 |
| `--host 0.0.0.0` | 允许局域网访问（**公共网络别开**，没有认证） |
| `--no-browser` | 不自动开浏览器（远程/调试用） |

依赖 `ui_params.py`（选项卡与参数表），两个文件必须一起更新。
各选项卡的功能与前面命令行那张表一一对应，只是把参数变成了输入框。

## 数据完整性

解出来带替换字符 `�`（U+FFFD），说明**原始数据本身缺字节**，不是脚本的问题。

- 干净解出 → 结果可信
- 带 `�` → 回头找更原始的来源（原帖、原始文件、更早的截图）

这条对任何编码都成立：base64 被截断、hex 是奇数长度、mojibake 缺字节，都会表现成 `�`。

`dec mojibake` 会把损失率算出来：0% 才认定还原成功，超过 2% 直接报错，而不是猜一个最像的硬输出。
例外是中日韩编码互相误读那一类——它本来就不该有损失，判据换成「结果是否显著更像正常文字」，
命中时会打一行 `[跨编码]` 告诉你用了哪对编码。

**输入本身带 `�` 时**（复制/转存时就丢了字节，不是解码产生的）走**分段还原**：
按 `�` 切开分别解，能救的救回来、救不了的留标记。缺几个字节不至于全丢，
`--best` 还会把缺失处显示成 `?` 更好读。

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

## 更新

```bash
git pull
```

或者网页上点 **Code → Download ZIP** 覆盖解压。**注意 ZIP 里 `data/words.txt` 要一起换**——
只更新 `.py` 会导致词表缺失，单表替换破解的准确率会下降（程序会提示降级）。

仓库是公开的，也可以单独下某个文件，不用克隆：

```bash
curl -O https://raw.githubusercontent.com/Seve0r/puzzle-toolkit/main/codec.py
```

> 国内直连 `raw.githubusercontent.com` 经常超时（curl 返回 000，不是 404）。
> 挂代理即可：`curl -x http://127.0.0.1:7897 -O https://raw.githubusercontent.com/...`

## 目录结构

```
puzzle-toolkit/
  codec.py        编码识别与解码
  classic.py      古典密码
  hashcrypto.py   哈希与现代密码
  stego.py        文件隐写
  data/words.txt  内置英语词表（约 1500 常用词）
  docs/
    codec.md      ← codec.py 的详细说明
    classic.md    ← classic.py
    hashcrypto.md ← hashcrypto.py
    stego.md      ← stego.py
  CHANGELOG.md    更新日志
```

## 依赖

只需要 Python 3.8+。

两个功能依赖外部命令，缺了不影响其余部分：

- `stego.py qr` 需要 `zbarimg`（`apt install zbar-tools`）
- `stego.py spec` 需要 `ffmpeg`
