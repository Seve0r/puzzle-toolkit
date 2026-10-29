---
name: stego-toolkit
description: Use when a file (image/audio/zip/document) may hide data — 图片隐写、LSB、png 块、exif、文件尾附加数据、binwalk、zip 伪加密、压缩包注释、音频频谱、摩斯隐写、二维码、CTF misc、ARG 素材取证。Scans magic numbers, dumps trailing data after IEND/EOI, extracts LSB across channels, parses PNG chunks and ZIP structures without external tools, and renders audio spectrograms.
---

# 文件隐写取证

```bash
S=~/.dsh/skills/stego-toolkit/scripts/stego.py
python3 $S <子命令> <文件>
```

| 子命令 | 用途 |
|---|---|
| `binwalk` | 扫描内嵌文件魔数（zip/png/jpg/gzip/pdf/rar/7z/sqlite/ELF/PEM） |
| `tail` | **查文件正式结束符之后还有没有东西**（最常见的一类隐写） |
| `strings` | 抽可打印串，自动标可疑（flag/URL/base64/长 hex/密码字样） |
| `lsb` / `lsbscan` | LSB 提取，rgb/rgba/r/g/b × 最低 2~3 位全扫 |
| `exif` | 元数据 + PNG 文本块（tEXt/zTXt/iTXt） |
| `pngchunks` | 逐个 PNG 块，标出非标准块 |
| `zipinfo` | 不依赖 unzip：条目、注释、**伪加密**标志 |
| `unzip` | 用标准库解压（支持 store/deflate） |
| `qr` | zbarimg 识别二维码，**自动放大 2×/4× 再试** |
| `spec` | ffmpeg 生成频谱图（看藏在音频里的字/摩斯） |
| `grid` | 点阵图切成格子读 bit 流，自动测格宽/相位/阈值，自动拼字节猜编码 |
| `meta` | 类型、大小、熵（熵 >7.9 说明加密或压缩过） |
| `hexdump` | 十六进制 + ASCII 对照 |

## 五个坑

**① LSB 绝对不能用"整体可打印率"筛选。**
图里藏 20 字节 flag 时，后面几万个字节全是图像噪声，整体可打印率不到 10%，
真正的答案会被直接过滤掉（这个 bug 实测漏掉过 `FLAG{...}`）。
正确做法：找**最长连续可打印片段**，长度 ≥ 8 字节就报。

**② 先查 `tail` 再查 LSB。**
按出现频率排序：文件尾附加数据 > EXIF/文本块 > LSB > 频谱。`tail` 一秒出结果，
而且证据最硬（`PNG IEND` 后面还有 132 字节，直接 hexdump 给你看）。

**③ ZIP 伪加密看"两个 flag 是否一致"。**
伪加密的手法是：中央目录标了"加密"，但局部文件头没标。
`zipinfo` 会并排列出 `local_flags` / `central_flags`，不一致就是伪加密，
把局部头那个 flag 字节改回 0 就能直接解压。

**④ 小二维码原图识别不出。**
`zbarimg` 对低于约 100×100 的二维码基本无能为力。`qr` 命令会自动放大 2×、4× 再试，
手写时记得自己先 resize。

**⑤ 频谱图是音频隐写的主力。**
`spec` 出图后**自己看**——文字、摩斯、坐标轴上的点都要人眼判断，
没有任何算法能替你认。对 ARG 尤其如此（参见 `bilibili-forensics` 里的频谱分析流程）。

## 点阵网格（grid）

**什么时候用**：一张小图放大后是「像素方块」，每块一格、每格一色，像是用格子
拼出来的。这类图的信息就是格子本身，`lsb` / `binwalk` 全都不管用，以前只能
靠人一个个数格子。

```bash
python3 $S grid puzzle.png
```

一行命令给齐：格数、经纬网格参数、ASCII 点阵、位流、字节 hexdump、解出的文本。

**它自己做的事**

1. **选通道**。对 R/G/B 三个通道各跑一次 Otsu，取「类间方差最大」的那个——
   青色底配深蓝块时红通道几乎没差别，绿通道差 200+，选错就全白干。
2. **测格宽和相位**。先算「相邻列的整列差」`prof[x] = Σ_y |G[x+1,y]-G[x,y]|`：
   格子内部是纯色，格线处才有峰。再用两个因子打分——
   `边界平均强度 / 全图平均强度` × `强峰覆盖率`，粗搜 0.25px 步长，再对前 6 个
   候选各自亚像素细化。
3. **取样**。每格取中心 50% 区域的平均色（避开模糊的格线），Otsu 定阈值二值化。
4. **拼字节**。按行（或 `--order col`）串成 bit 流，每 8 位一字节，先试 UTF-8
   再试 GB18030；解不出就自动把「深色=1」翻成「浅色=1」再试一遍。

**为什么是这个判据（三个都要，缺一个就翻车）**

- 分母用**全图平均**而不是「内部平均」：边缘锐利的图内部差恒为 0，拿它做分母
  会除零爆炸，挑出格宽 4.1 这种假周期。
- 乘**覆盖率**：边界数一少，几个最陡的点就能把均值刷高（实测选出过「格宽 117」，
  整张图只切 3 格）。强峰只可能来自格线——相邻同色时格线没有峰，反过来不成立——
  靠这条不对称性卡住。
- 粗搜**必须带小数**：缩放过以后格宽是 10.66 这种，整数周期会一路漂移、得分被
  「格宽 32」这种侥幸对齐三个峰的错误周期反超，细化就再也回不去。

**覆盖与已知局限**

| 选项 | 用途 |
|---|---|
| `--cols N` / `--rows N` | 直接指定格数，绕过自动检测 |
| `--cell 12.9x12.9` | 指定格宽/格高 |
| `--off 6.5,12.5` | 指定第一格起点的 x,y |
| `--channel r\|g\|b` | 强制通道 |
| `--threshold N` | 强制二值化阈值 |
| `--invert` | 强制「深色=1」，**不再自动翻色** |
| `--order col` | 按列读位流 |

- **图边缘是留白还是格子内容，靠颜色方差猜**（留白那条方差小）。留白宽度恰好
  接近一格时会判错，用 `--cols`/`--rows` 手动钉住。
- 显式给的 `--threshold` 如果把所有格子判成同一类，会**自动退回 Otsu** 并说明；
  否则输出一整片 `###`，完全看不出哪儿错了。
- 位流不是 8 的倍数时，末尾几位会被丢掉（会提示）。
- 图上如果**另外叠了线**（比如别人截图时画的红色网格）会被当成格线，结果全乱。
  要原始图。
- 输入 PNG 走**内置解码器**（不装 Pillow 也能用），但只支持非隔行；JPEG/WebP/GIF
  要装 Pillow。

**实测**（ERIKO #009 那张）：427×159、格宽 12.94、32×11 格，读到 352 位 = 44 字节，
按行拼成 UTF-8 得 `禁食洗净祷告刺冠饮圣天堂之门`，全程 0.2 秒。

## 环境依赖

| 功能 | 依赖 | 本机 |
|---|---|---|
| LSB / exif / pngchunks | Pillow | ✅ |
| grid（PNG 输入） | **无**（内置 PNG 解码器） | ✅ |
| grid（JPEG/WebP/GIF 输入） | Pillow | ✅ |
| qr | `zbarimg`（zbar-tools） | ✅ |
| spec | `ffmpeg` | ✅ |
| binwalk / zipinfo / zip 解压 | **无**（纯标准库实现） | ✅ |

本机**没有** `binwalk`、`zsteg`、`steghide`、`exiftool`、`john`，
所以这些能力都自己实现了，别指望命令行工具。

## 典型流程

```bash
python3 $S meta     suspicious.png     # 类型/熵
python3 $S tail     suspicious.png     # 尾附加
python3 $S strings  suspicious.png     # 可疑串
python3 $S exif     suspicious.png     # 元数据/文本块
python3 $S binwalk  suspicious.png     # 内嵌文件
python3 $S lsb      suspicious.png     # 像素位
python3 $S pngchunks suspicious.png    # 非标准块
```
