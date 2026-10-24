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

## 环境依赖

| 功能 | 依赖 | 本机 |
|---|---|---|
| LSB / exif / pngchunks | Pillow | ✅ |
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
