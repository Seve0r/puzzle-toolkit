---
name: classic-cipher
description: Use when solving classical/hand ciphers or CTF-style puzzles — 凯撒、ROT、维吉尼亚、仿射、单表替换、培根、栅栏、列置换、Atbash、A1Z26、波利比奥斯、普莱菲尔、ADFGX、键盘错位、手机九宫格 T9、ARG 解谜里的古典加密。Does keyless cracking (Vigenère auto-solve, Caesar/affine/railfence brute force, frequency-based substitution hill-climb) and prints ranked candidates with an English-likeness score.
---

# 古典密码工具箱

```bash
C=~/.dsh/skills/classic-cipher/scripts/classic.py
python3 $C <子命令> <文本>
```

| 子命令 | 作用 |
|---|---|
| `caesar` | 不给 `--key` 就 26 个偏移全爆破，按英文契合度排序 |
| `vigenere --key K` | 维吉尼亚；`--enc` 加密 |
| `vigcrack` | **无密钥自动破解**（自动定长 + 逐列解 + 密钥微调） |
| `affine` | 不给 `--a/--b` 就 312 种全爆破；`affine-enc --a 5 --b 8` 加密 |
| `sub` | 单表替换爬山破解（**需要 300 字母以上**，见下） |
| `bacon` | 培根，吃 `A/B` 串，也能从大小写隐写里读 |
| `railfence` | 不给 `--rails` 就全爆破 |
| `columnar --key K` | 列置换；不给 key 就按长度排列爆破 |
| `atbash` / `a1z26` / `polybius` | 直接解（`--enc` 转成编码） |
| `playfair --key K` | 普莱菲尔方阵 |
| `adfgx --key K [--trans T]` | ADFGX |
| `keyboard --all` | 键盘错位（qwerty/dvorak/azerty × 平移量） |
| `t9 <数字>` | 九宫格列出所有可能，按英文排序 |
| `auto` | 全部跑一遍汇总排名 |

## 四个必须知道的坑（都是实测踩出来的）

**① chi² 在短文本上会反向误导。**
十几个字母的英文天然"每个字母各出现一次"，chi² 会判它**极不像**英文；而均匀分布的
乱码反而得分高。所以 30 字母以下 chi² 权重直接归零，只信 bigram。阈值随长度平滑过渡。

**② bigram 不能累加，必须除以长度。**
早期版本 `sum(bigrams) * 4`，结果"一半正确一半乱码"的文本得分比完美明文还高
（乱码凑出的 th/he/en/an 把分数顶上去），破解器专门挑假密钥。现在一律归一化。

**③ 维吉尼亚不能用 IC 判密钥长度。**
IC 对密钥的**整数倍**特别敏感——密钥 6 位时，12 位、18 位的 IC 一样高甚至更高。
按 IC 排序经常选出假长度，解出乱七八糟的"半通顺"文本。
正确做法：2..N 每个长度都完整解一遍按明文质量排名，最后用**最小周期**把
`secretsecret` 收敛回 `secret`。

**④ 逐列频率分析偶尔错一两个字母。**
某一列碰巧缺高频字就会解错。所以破解完必须对整段明文做一次**坐标下降微调**——
逐个字母试 26 种替换，保留整体得分最高的。加这一步后 9/9 密钥全中（不加只有 2/9）。

## 单表替换（`sub`）的长度红线

用词表做"能切成多少真单词"的覆盖率评分，比 bigram 强得多。
词表按顺序取第一个可用的：`PUZZLE_WORDLIST` 环境变量 → 仓库内 `data/words.txt`
→ 系统词典 `/usr/share/dict/words`（Linux / macOS）。Windows 上没有系统词典，
会用 `data/words.txt`；一份都找不到时会在 stderr 明确提示降级，不会静默变成纯 bigram。
但**词表信号在短文本上会反向误导**（错误映射也能切出一堆假词），
所以权重随长度增加，250 字母以上才给满。

实测：
- **330 字母 → 完美还原**（1 秒）
- **225 字母 → 失败**
- 132 字母 → 失败

结论：**少于 300 字母别指望自动解**，先看有没有线索能猜出部分映射（已知明文攻击）。

顺带：词表只认 3 字母以上的词。双字母词（in/at/do）在乱码里到处能凑出来，
会让乱码覆盖率虚高到 0.9，区分度直接没了。

## 填充与歧义（playfair / a1z26）

**`playfair` 默认严格互逆，不去填充。** 加密时相邻重复字母（`letter` 的 `tt`）
会插入 `x` 拆开，奇数长度末尾补 `x`，所以解密结果里会带着这些 `x`：

```
letter  --enc-->  ulszlkaz  --解密-->  letxterx
```

这是数学上正确的还原（原文 + 中间插入的 x + 末尾填充 x）。想直接拿原文就加 `--clean`：

```
classic.py playfair --key K --clean "ulszlkaz"    # -> letter
```

**`--clean` 有已知误伤**：原文本身含 `xax` 结构时会被一并删掉，例如 `taxa` → `taa`。
所以默认不清理——宁可多留痕迹，也不静默改动用户数据。

**`a1z26` 分两种输入，处理方式不同：**

- **有分隔符**（`"1 12 3"`、`"1,12,3"`）→ 每个数就是一个字母，绝不合并。
  早期版本在这里会贪心把 `1` 和 `12` 拼成 `22` → `v`，解出 `vc` 而不是 `alc`，已修。
- **连续数字串**（`"1123"`）→ 切分本身有歧义
  （`1-1-2-3` / `11-2-3` / `11-23` / `1-12-3`），枚举所有合法切分，
  按英文契合度取最好的那个。

## 推荐流程

1. `auto` 先扫一遍，看有没有直接中的
2. `caesar` 看 26 个候选（短文本尤其快）
3. 字母频率明显不像单表替换（IC 明显低于 0.0667）→ 上 `vigcrack`
4. 结果是 5×5 坐标、A/D/F/G/X 字母、或 AB/01 分组 → 分别是 `polybius`、`adfgx`、`bacon`

## 没有内置的

- **猪圈密码**（Pigpen）：输入通常是图片不是文本，手算更快。标准映射是
  `ABC/DEF/GHI` 三格、`JKL/MNO/PQR` 带点三格、`STUV` 和 `WXYZ` 两个 X 形。
- **恩尼格玛**：状态机复杂，用现成工具（py-enigma）比自己写靠谱。
