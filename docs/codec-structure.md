# `codec.py` 结构图

> **本文只描述 `codec.py` 这一个脚本的代码布局。**
> 其他脚本（`classic` / `hashcrypto` / `stego` / `num` / `ui`）的用法见各自的
> `docs/<脚本>.md`；本文件不讲怎么用，只讲代码长在哪。
>
> 使用者要的是命令手册 → 看 `README.md` 和 `docs/codec.md`。
> 维护者要的是"改这东西该动哪一段" → 就是这个文件。

规模：**2745 行 / 156 个顶层对象 / 72 个注册名**（`DECODERS` 72、`ENCODERS` 68，
差的 4 个是只解不编的 `braillebits` / `mojibake` 这类）。

---

## 一、分层总览

| 区 | 行范围 | 行数 | 对象 | 干什么 |
|---|---|---:|---:|---|
| 文件头 | 1–63 | 63 | — | docstring（也就是 `--help` 的内容）+ import |
| 基础设施 | 64–121 | 58 | 8 | 两张注册表、两个装饰器、`str ↔ bytes` 出入口 |
| Base 系列 | 122–347 | 226 | 25 | base64/32/58/62/85/91/36 等 8 对 |
| 进制 / 二进制串 | 348–450 | 103 | 10 | hex·bin·dec·oct·block36 |
| Punycode | 451–499 | 49 | 4 | IDN 编码 |
| 文本转义 | 500–578 | 79 | 10 | url / html / unicode / js / quoted-printable |
| 字符替换 | 579–630 | 52 | 7 | rot13 / rot47 / atbash（自反变换） |
| 摩斯 | 631–678 | 48 | 4 | 国际摩斯 + 两张表 |
| 和文モールス | 679–832 | 154 | 10 | Wabun code + 6 张表/工具 |
| 盲文 | 833–920 | 88 | 8 | 2 解码 + 1 编码 + 5 张表 |
| 压缩流与字符编码 | 921–1029 | 109 | 12 | zlib/uu + utf16 + gbk |
| UTF-32 | 1030–1081 | 52 | 7 | utf32/be/le |
| **乱码还原** | 1082–1803 | **722** | 23 | 多层假设流水线，见第三节 |
| 评分 / 识别 | 1804–2109 | 306 | 12 | `score` / `structural_candidates` / `auto` / `brute` |
| 矩阵重排 | 2110–2175 | 66 | 3 | `grid` |
| 编码 × 进制 | 2176–2388 | 213 | 11 | `convert` |
| CLI | 2389–2745 | 357 | 2 | `read_input` → `main` |

**每个编码概念的 `_d_*` / `_e_*` 都是相邻的**（实测间距 ≤60 行）。
这是 2026-11 重排的结果——之前编码器全堆在文件末尾，最远的
`base32hex` 和它的解码端相隔 2150 行，改一个编码要开两个地方。

---

## 二、逐区

```
【基础设施】L64-121
  DECODERS / ENCODERS            两张 dict，装饰器往里塞
  dec_name(*names) / enc_name()  一个函数可以挂多个名字（正式名 + 别名）
  as_bytes / raw_bytes           str → bytes。区别：前者走 latin-1 承载，后者认两种形态
  as_text / _bin_str             bytes → str。_bin_str 用 latin-1 保证 1 字符 = 1 字节

【Base 系列】L122-347
  base64/b64 · base64url · base32/b32 · base32hex/b32hex · base16/hex
  base58/b58/base58btc · base62/b62 · base85/b85 · ascii85/a85
  base91/b91 · base36/b36
  常量：B58_ALPHABET、B62_SETS（三套字母表）、B91

【进制 / 二进制串】L348-450
  bin/binary · dec/decimal · oct/octal   ← 都是「一串数 → 字节」
  blocks_to_bytes + _B36_ALPHA + block36/b36x2   ← 「两位 base36 = 一字节」
  注意 base36 和 block36 不是一回事：前者整串当大整数，后者每两位一个字节

【Punycode】L451-499       punycode/puny/idn
【文本转义】L500-578       url · html · unicode · js · qp
【字符替换】L579-630       _rot_n → rot13 / rot47 / atbash（自反：enc 就是再 dec 一次）

【摩斯】L631-678           MORSE / MORSE_REV + morse
【和文モールス】L679-832   WABUN / WABUN_REV / _WABUN_DAKU / _WABUN_HANDAKU
                           _kata2hira / _hira2kata / _wabun_near / _WABUN_SMALL
                           注意：没有小假名（ャュョッ）的独立符号，统一按大假名送

【盲文】L833-920           braille（解+编）、braillebits（只解，点阵位流形态）
【压缩流与字符编码】L921-1029
  compress（gzip/zlib/bz2/deflate/inflate 共用一对函数）· uu
  utf16/be/le · gbk
  二进制结果统一用 latin-1 承载（1 字符 = 1 字节），要落文件请套 enc hex

【UTF-32】L1030-1081       _u32_input（输入归一）+ utf32/be/le

【评分 / 识别】L1804-2109
  score                    可读性打分（比例类，短串会失真）
  acceptable               长度骤减 / 控制字符的否决
  structural_candidates    结构指纹：这串像什么编码
  try_decode               按名字解一次，失败返回 None
  brute                    全试一遍按分排序（这里才带上 rot13/47/atbash）
  auto                     递归剥皮，默认深度 3
  COMMON_EN / COMMON_CN / CJK_RE / STRUCT_BONUS / LOOSE_ORDER / MIN_OUT_RATIO

【矩阵重排】L2110-2175     _blocks / _read / grid_variants

【编码 × 进制】L2176-2388
  _RADIX_*（字符集、标签、分隔符）
  _radix_clean / _radix_bad_chars   ← 先去分隔符，再校验字符集
  radix_to_bytes                     ← 报错顺序：字符集 → 长度 → 范围
  encoding_candidates                ← 扫出所有能完整解出的编码
  bytes_to_text                      ← auto 是「挑一个」不是「它就是」
  convert_decode                     ← CLI 与界面共用

【CLI】L2389-2745
  read_input    多吃一个参数：`-f` 文件 / 管道 / argv 拼接
  main          手写参数解析 + 子命令分发（没有通用 opt 库）
```

---

## 三、乱码还原（`mojibake`）：唯一需要拆层看的区

**为什么单独展开**：文件里别处都是「一个编码 = 一对函数」，看一眼就知道在干什么。
这里不一样——它是**多层假设、逐级降级**的流水线，23 个对象横跨 722 行，
而且每层能接住的情况互不重叠。不理解层的顺序，改一个阈值就会连带弄坏别层。

### 3.1 调度顺序（`_d_mojibake`, L1513）

```
_d_mojibake(s)
 ├─ 纯 ASCII                        → 直接拒绝（不可能是误读）
 ├─ 长度 < 3                        → 直接拒绝（单字会被"无损"凑出假结果）
 │
 ├─ 一级   mojibake_rank    目标 UTF-8
 │        损失率 ≤2% 且 _plain 不显著变差 → 采信
 │
 ├─ 1.5 级 mojibake_latin1  整串西欧字符
 │        【实验开关 _ENABLE_LATIN1_MOJIBAKE，默认关】
 │
 ├─ 二级   mojibake_cross   目标不是 UTF-8（中日韩互相误读）
 │        判据换成「可读度有没有明显提升」
 │
 ├─ 三级   mojibake_split   原文含 U+FFFD（字节已丢），分段还原
 │
 └─ 都不成 → 报「数据可能残缺」，不硬给结果
```

无歧义的显式路径 `mojibake_explicit`（`--from A --to B`）不走上面任何一级，
直接照办。

### 3.2 判据层（只打分，不下结论）

| 函数 | 量什么 | 分母 | 用在哪 |
|---|---|---|---|
| `_encodable(ch, enc)` | 这个字符能否用 `enc` 表示 | — | 上面几个判据的底层，带 `_ENC_CACHE` 缓存（试编很贵） |
| `_plain(s)` | 像不像正常文字 | **全部字符** | 一级/二级的候选筛选 |
| `_common_ratio(s)` | 「一看就是正常文字」的占比 | **全部字符** | 跨编码判据的**基准线**（跟原文比提升） |
| `_han_ratio(s)` | CJK 汉字占比 | **全部字符** | 跨编码假设的**准入门槛** |
| `readability(s)` | 「正常文字占比」 | **只算中日韩** | 判断「解够了没有」，`--deep` 的阈值 |
| `_same_encoding_family(a,b)` | 两个编码是否同族 | — | 过滤掉「互相转码等于没转」的组合 |

三个"可读度"看着像，其实分工不同，别混用：

- **`_plain`** 判定放宽到 Shift_JIS（要认日文新字体 実/嘘），所以 GBK 罕用字
  （僂/僣/僉）也能拿分——它适合**筛候选**，不适合当提升基准。
- **`_common_ratio`** 只认真正高频的东西（GB2312 常用汉字、假名、ASCII、CJK 标点），
  乱码产物一个都不是，所以基准是 0。跨编码判断「有没有提升」必须用它。
  （拿 `_plain` 当基准会把 `僂僜僣僉 → ウソツキ` 这种正确解误杀。）
- **`readability`** 分母**只算中日韩**，ASCII 不计入。否则解过头变成 `?1?7?1?7`
  这种 ASCII 噪音时反而得高分，`--deep` 会一路解到烂。它服务于「迭代到什么时候停」。

### 3.3 每层的假设

| 层 | 假设 | 典型输入 | 判据 |
|---|---|---|---|
| 一级 `mojibake_rank` | 原始是 UTF-8，被别的编码**读**成了这些字 | `浜哄彧` → `人只` | U+FFFD 损失率 ≤2%（无损才说明猜对） |
| 1.5 级 `mojibake_latin1` | 每个**字符**就是一个字节（西欧字符类） | `²âÊÔ` → `测试` | 高位字符占比 + 常用字比例，**实验开关控制** |
| 二级 `mojibake_cross` | 原始字节被**非 UTF-8** 的编码解了 | `孨偼堦惗…` → `君は一生私を忘れない` | 可读度明显提升 + `_han_ratio` 过门槛 |
| 三级 `mojibake_split` | 字节**已经丢了**（原文含 U+FFFD） | 复制/转存坏了的数据 | 分段还原，缺失处标 `?` |
| 显式 `mojibake_explicit` | 用户知道当初的编码对 | `--from gbk --to shift_jis` | 不猜 |

一级的坑：**无损不等于正确**。`あいうえお → ƦƨƪƬƮ`、`茻 → Ɵ` 都是 0 损失却纯是垃圾。
所以还要 `_plain(out) >= _plain(s) - 0.05`。但门槛只能设成「不许变差」不能设成
「必须变好」——`浣犲ソ → 你好` 里原文含一个假名 ソ，`_plain` 本来就是 1.0，
要求严格提升会把正确解判掉。

### 3.4 上层封装

| 函数 | 职责 |
|---|---|
| `text_encoding_name(s)` | 给解出来的文本贴编码标签，用于报告。纯 ASCII 时写「与编码无关」 |
| `auto_with_mojibake(text, depth)` | `auto` 的完整版：没找到可靠路径时再认真试一次 mojibake。**界面也走这条**，不能只在 CLI 里加 |
| `mojibake_best(text)` | 宽松还原：不管损失多大都返回最佳假设，缺失处标 `?` |
| `mojibake_deep(text, threshold)` | 反复还原直到 `readability` 达标（`--deep`） |

### 3.5 模块级常量

```
MOJIBAKE_ENCODINGS   「把字节解成乱码」的候选编码（cp932 排在 shift_jis 前）
_GBK_FAMILY          哪些编码算 GB 家族
MOJIBAKE_TARGETS     「把文字编成字节」的候选编码
_MOJIBAKE_FAMILIES   上两者的族分组
```

### 3.6 实验开关

```python
_ENABLE_LATIN1_MOJIBAKE = False   # L1148
```

同时控制三处：`mojibake_latin1()`、`_encode_back()` 里的 NFC 归一、
`auto_with_mojibake()` 的兜底。关掉的原因见 `TODO.md`：文件名乱码的真实样本
还不够，担心误伤。代码全部保留，改成 `True` 就恢复。

---

## 四、改代码时从哪下手

| 想做什么 | 去哪 |
|---|---|
| 加一个新编码 | 找到同类区，`_d_xxx` 和 `_e_xxx` **紧挨着写**，两处都要 `@dec_name` / `@enc_name` |
| 某个编码解不出来 | 先看它的 `_d_*`，再看 `structural_candidates`（L1904 附近）有没有认它 |
| `auto` 选错了路径 | `structural_candidates` 的候选顺序 + `STRUCT_BONUS` 权重 |
| 报告里的编码名不对 | `text_encoding_name`（L1621）/ `bytes_to_text`（L2304） |
| 乱码还原过度/不足 | 先判断是哪一层（看 stderr 的提示），再调那一层的阈值，**别动别层** |
| 进制解析报错不对 | `radix_to_bytes`（L2230）：顺序必须是 字符集 → 长度 → 范围 |
| 加子命令 | `main`（L2439）；参数解析是手写的，没有通用 `opt()` |
| 界面相关 | 不在本文件。`ui.py`（渲染/事件）+ `ui_params.py`（参数表） |

---

## 五、两个已知的"不对称"

不是 bug，是历史决定的，改之前要知道：

1. **`braillebits` 只解不编**。它是点阵位流形态（每格 1 bit），没有唯一的反向编码。
2. **`gbk` 的 `enc` 不是「文本 → GBK 字节」**。`_e_gbk` 和 `_d_gbk` 干的其实是
   同一件事——「把输入当字节、按 GBK 解成文本」：

   ```python
   @enc_name("gbk")
   def _e_gbk(s):
       return as_bytes(s).decode("gbk", "replace")
   ```

   所以 `enc gbk hi` 得到 `hi`（ASCII 在哪种编码下都一样，看不出问题），
   而 `enc gbk 浣犲ソ` 得到 `娴ｇ姴銈`——它把结果又当字节读了一遍。

   **codec 里没有「文本 → 指定编码字节」的命令**（`convert` 走的是解码链：
   文本 → 字节 → 按编码解回文本）。真需要 GBK 字节时用 Python 一行：

   ```bash
   python3 -c "print('你好'.encode('gbk').hex())"   # c4e3bac3
   codec convert c4e3bac3 -r 16 -e gbk              # 解回 你好（这个方向是通的）
   ```

另外二进制类结果（压缩流 / utf16 / utf32 / uu）经 stdout 时会按文本编码写坏，
**要落文件请套 `enc hex`**——这是承载方式决定的，不是 bug。

---

维护提示：本文的行号会随代码变动而漂移。核对办法是 `grep -n "^# ---" codec.py`
看区标题的当前位置；区名是稳定的，行号不是。
