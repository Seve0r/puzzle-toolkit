# 脚本结构图

> **维护者视角**：代码长在哪、改哪里该动哪一段。
> 用法（怎么用这些命令）看 `README.md` 和 `docs/<脚本>.md`，本文件不讲用法。
>
> 分区行号会随改动漂移，**区名是稳定的**。核对办法：
> `grep -n "^# ---" <脚本>.py`

| 脚本 | 行数 | 顶层对象 | 分区 | 最长函数 | 职责 |
|---|---:|---:|---:|---|---|
| `codec.py` | 3217 | 187 | 16 | `main` 370 行 | 编码识别与解码 |
| `classic.py` | 1769 | 109 | 18 | `main` 268 行 | 古典密码 |
| `hashcrypto.py` | 1161 | 50 | 8 | `main` 283 行 | 哈希与现代密码 |
| `stego.py` | 1434 | 54 | 7 | `main` 229 行 | 文件隐写 |
| `num.py` | 227 | 13 | — | `main` 96 行 | 进制转换（数值视角） |
| `ui.py` | 1941 | 43 | 4 | `run_action` 182 行 | 本地界面（HTTP + 内嵌 HTML/JS） |
| `ui_params.py` | 489 | 21 | 8 | `_pigpen_slots_json` 22 行 | 界面参数表（纯数据，不 import codec） |

---

## 一、`codec.py`

### 1. 分层总览

| 区 | 行范围 | 行数 | 对象 | 干什么 |
|---|---|---:|---:|---|
| 文件头 | 1–67 | 67 | — | docstring（也就是 `--help` 的内容）+ import |
| 基础设施 | 68–158 | 91 | 11 | 两张注册表、两个装饰器、`str ↔ bytes` 出入口、`_hint`（`-q` 的静默出口） |
| Base 系列 | 159–485 | 327 | 27 | base64/32/58/62/85/91/36 等 8 对 |
| 进制 / 二进制串 | 486–594 | 109 | 10 | hex·bin·dec·oct·block36 |
| Punycode | 595–643 | 49 | 4 | IDN 编码 |
| 文本转义 | 644–729 | 86 | 10 | url / html / unicode / js / quoted-printable |
| 字符替换 | 730–781 | 52 | 7 | rot13 / rot47 / atbash（自反变换） |
| 摩斯 | 782–829 | 48 | 4 | 国际摩斯 + 两张表 |
| 和文モールス | 830–1000 | 171 | 11 | Wabun code + 6 张表/工具 |
| 盲文 | 1001–1088 | 88 | 8 | 2 解码 + 1 编码 + 5 张表 |
| 压缩流与字符编码 | 1089–1205 | 117 | 12 | zlib/uu + utf16 + gbk |
| UTF-32 | 1206–1257 | 52 | 7 | utf32/be/le |
| **乱码还原** | 1258–2106 | 849 | 27 | 多层假设流水线，见第三节 |
| 评分 / 识别 | 2107–2474 | 368 | 13 | `score` / `structural_candidates` / `auto` / `brute` |
| 矩阵重排 | 2475–2540 | 66 | 3 | `grid` |
| 编码 × 进制 | 2541–2793 | 253 | 13 | `convert` |
| CLI | 2794–3217 | 424 | 3 | `read_input` → `main` |

**每个编码概念的 `_d_*` / `_e_*` 都是相邻的**（实测间距 ≤60 行）。
这是 2026-11 重排的结果——之前编码器全堆在文件末尾，最远的
`base32hex` 和它的解码端相隔 2150 行，改一个编码要开两个地方。

---

### 2. 逐区

```
【基础设施】L64-154
  DECODERS / ENCODERS            两张 dict，装饰器往里塞
  dec_name(*names) / enc_name()  一个函数可以挂多个名字（正式名 + 别名）
  as_bytes / raw_bytes           str → bytes。区别：前者走 latin-1 承载，后者认两种形态
  as_text / _bin_str             bytes → str。_bin_str 用 latin-1 保证 1 字符 = 1 字节
  _QUIET / _hint(msg)            诊断提示的统一出口，`-q` 时静默；错误信息不走这里

【Base 系列】L155-413
  base64/b64 · base64url · base32/b32 · base32hex/b32hex · base16/hex
  base58/b58/base58btc · base62/b62 · base85/b85 · ascii85/a85
  base91/b91 · base36/b36
  常量：B58_ALPHABET、B62_SETS（三套字母表）、B91

【进制 / 二进制串】L414-522
  bin/binary · dec/decimal · oct/octal   ← 都是「一串数 → 字节」
  blocks_to_bytes + _B36_ALPHA + block36/b36x2   ← 「两位 base36 = 一字节」
  注意 base36 和 block36 不是一回事：前者整串当大整数，后者每两位一个字节

【Punycode】L523-571       punycode/puny/idn
【文本转义】L572-650       url · html · unicode · js · qp
【字符替换】L651-702       _rot_n → rot13 / rot47 / atbash（自反：enc 就是再 dec 一次）

【摩斯】L703-750           MORSE / MORSE_REV + morse
【和文モールス】L751-921   WABUN / WABUN_REV / _WABUN_DAKU / _WABUN_HANDAKU
                           _kata2hira / _hira2kata / _wabun_near / _WABUN_SMALL
                           注意：没有小假名（ャュョッ）的独立符号，统一按大假名送

【盲文】L922-1009           braille（解+编）、braillebits（只解，点阵位流形态）
【压缩流与字符编码】L1010-1118
  compress（gzip/zlib/bz2/deflate/inflate 共用一对函数）· uu
  utf16/be/le · gbk
  二进制结果统一用 latin-1 承载（1 字符 = 1 字节），要落文件请套 enc hex

【UTF-32】L1119-1170       _u32_input（输入归一）+ utf32/be/le

【评分 / 识别】L2012-2379
  score                    可读性打分（比例类，短串会失真）
  acceptable               长度骤减 / 控制字符的否决
  structural_candidates    结构指纹：这串像什么编码
  try_decode               按名字解一次，失败返回 None
  brute                    全试一遍按分排序（这里才带上 rot13/47/atbash）
  auto                     递归剥皮，默认深度 3
  COMMON_EN / COMMON_CN / CJK_RE / STRUCT_BONUS / LOOSE_ORDER / MIN_OUT_RATIO

【矩阵重排】L2380-2445     _blocks / _read / grid_variants

【编码 × 进制】L2446-2698
  _RADIX_*（字符集、标签、分隔符）
  _radix_clean / _radix_bad_chars   ← 先去分隔符，再校验字符集
  radix_to_bytes                     ← 报错顺序：字符集 → 长度 → 范围
  encoding_candidates                ← 扫出所有能完整解出的编码
  bytes_to_text                      ← auto 是「挑一个」不是「它就是」
  convert_decode                     ← CLI 与界面共用

【CLI】L2699-3122
  read_input    多吃一个参数：`-f` 文件 / 管道 / argv 拼接
  main          手写参数解析 + 子命令分发（没有通用 opt 库）
```

---

### 3. 乱码还原（`mojibake`）：唯一需要拆层看的区

**为什么单独展开**：文件里别处都是「一个编码 = 一对函数」，看一眼就知道在干什么。
这里不一样——它是**多层假设、逐级降级**的流水线，23 个对象横跨 722 行，
而且每层能接住的情况互不重叠。不理解层的顺序，改一个阈值就会连带弄坏别层。

#### 3.1 调度顺序（`_d_mojibake`, L1778）

```
_d_mojibake(s)                ← 进来先 _mb_clean(s)：去掉首尾 ASCII 空白
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

#### 3.2 判据层（只打分，不下结论）

| 函数 | 量什么 | 分母 | 用在哪 |
|---|---|---|---|
| `_encodable(ch, enc)` | 这个字符能否用 `enc` 表示 | — | 上面几个判据的底层，`lru_cache(65536)` 缓存（试编很贵，上限约 8 MB） |
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
  （拿 `_plain` 当基准会把 `僥僗僩梡 → ウソツキ` 这种正确解误杀。）
- **`readability`** 分母**只算中日韩**，ASCII 不计入。否则解过头变成 `?1?7?1?7`
  这种 ASCII 噪音时反而得高分，`--deep` 会一路解到烂。它服务于「迭代到什么时候停」。

#### 3.3 每层的假设

| 层 | 假设 | 典型输入 | 判据 |
|---|---|---|---|
| 一级 `mojibake_rank` | 原始是 UTF-8，被别的编码**读**成了这些字 | `缂栫爜` → `编码` | U+FFFD 损失率 ≤2%（无损才说明猜对） |
| 1.5 级 `mojibake_latin1` | 每个**字符**就是一个字节（西欧字符类） | `²âÊÔ` → `测试` | 高位字符占比 + 常用字比例，**实验开关控制** |
| 二级 `mojibake_cross` | 原始字节被**非 UTF-8** 的编码解了 | `僥僗僩梡…` → `テスト用の文字列` | 可读度明显提升 + `_han_ratio` 过门槛 |
| 三级 `mojibake_split` | 字节**已经丢了**（原文含 U+FFFD） | 复制/转存坏了的数据 | 分段还原，缺失处标 `?` |
| 显式 `mojibake_explicit` | 用户知道当初的编码对 | `--from gbk --to shift_jis` | 不猜 |

一级的坑：**无损不等于正确**。`あいうえお → ƦƨƪƬƮ`、`茻 → Ɵ` 都是 0 损失却纯是垃圾。
所以还要 `_plain(out) >= _plain(s) - 0.05`。但门槛只能设成「不许变差」不能设成
「必须变好」——`缂栫爜 → 你好` 里原文含一个假名 ソ，`_plain` 本来就是 1.0，
要求严格提升会把正确解判掉。

#### 3.4 上层封装

| 函数 | 职责 |
|---|---|
| `text_encoding_name(s)` | 给解出来的文本贴编码标签，用于报告。纯 ASCII 时写「与编码无关」 |
| `auto_with_mojibake(text, depth)` | `auto` 的完整版：没找到可靠路径时再认真试一次 mojibake。**界面也走这条**，不能只在 CLI 里加 |
| `mojibake_best(text)` | 宽松还原：不管损失多大都返回最佳假设，缺失处标 `?` |
| `mojibake_deep(text, threshold)` | 反复还原直到 `readability` 达标（`--deep`）。**每层若含 U+FFFD 就按它切段分别还原**，见下 |
| `_mb_layer(s)` | 跑一层：先 UTF-8 假设、不行再试跨编码。从 deep 的循环体里抽出来的——分段还原时每段都要跑同一套顺序 |
| `_mb_clean(s)` | 所有 mojibake 入口的公共前置：去首尾 **ASCII** 空白（全角空格 U+3000 不碰，它在乱码里可能是真数据） |

**为什么每层要检查 U+FFFD**：`gb18030` 给 U+FFFD 也留了编码位
（`84 31 a4 37`）。整段编回去时，这个「此处无数据」的标记会被当成 4 个
真实字节解出来，在正确答案后面拖一条垃圾尾巴——实测目标
`编码??试` 被解成 `编码??试幄1?7`。所以含 U+FFFD 时必须
按它切段，丢失位置原样保留。

**为什么入口要 strip 空白**：粘贴进命令行/输入框的文本很容易带换行。
显式编码对逐字节对齐，末尾多 1 字节后果差别很大：38 字节报
「结尾被截断」（unexpected end of data），39 字节就变成「非法续接字节」
（invalid continuation byte）——后者看起来像数据损坏，实际只是多了个 `\n`。

#### 3.5 模块级常量

```
MOJIBAKE_ENCODINGS   「把字节解成乱码」的候选编码（cp932 排在 shift_jis 前）
_GBK_FAMILY          哪些编码算 GB 家族
MOJIBAKE_TARGETS     「把文字编成字节」的候选编码
_MOJIBAKE_FAMILIES   上两者的族分组
```

#### 3.6 实验开关

```python
_ENABLE_LATIN1_MOJIBAKE = False   # L1237
```

同时控制三处：`mojibake_latin1()`、`_encode_back()` 里的 NFC 归一、
`auto_with_mojibake()` 的兜底。关掉的原因见 `TODO.md`：文件名乱码的真实样本
还不够，担心误伤。代码全部保留，改成 `True` 就恢复。

---

### 4. 改代码时从哪下手

| 想做什么 | 去哪 |
|---|---|
| 加一个新编码 | 找到同类区，`_d_xxx` 和 `_e_xxx` **紧挨着写**，两处都要 `@dec_name` / `@enc_name` |
| 某个编码解不出来 | 先看它的 `_d_*`，再看 `structural_candidates`（L2207 附近）有没有认它 |
| `auto` 选错了路径 | `structural_candidates` 的候选顺序 + `STRUCT_BONUS` 权重 |
| 报告里的编码名不对 | `text_encoding_name`（L1880）/ `bytes_to_text`（L2669） |
| 乱码还原过度/不足 | 先判断是哪一层（看 stderr 的提示），再调那一层的阈值，**别动别层** |
| 进制解析报错不对 | `radix_to_bytes`（L2595）：顺序必须是 字符集 → 长度 → 范围 |
| 加子命令 | `main`（L2844）；参数解析是手写的，没有通用 `opt()` |
| 界面相关 | 不在本文件。`ui.py`（渲染/事件）+ `ui_params.py`（参数表） |

---

### 5. 两个已知的不对称

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
   而 `enc gbk 缂栫爜` 得到 `娴ｇ姴銈`——它把结果又当字节读了一遍。

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


---

## 二、`classic.py`

1769 行 / 109 个顶层对象 / 18 个分区。

**结构特点：一个密码一个区，`xxx_dec` 和 `xxx_enc` 相邻。** 这点和 `codec.py`
相反——codec 曾经把编码器全堆在文件末尾（2026-11 才归位），classic 从一开始
就是配对的，10 组编解码全部紧挨。

| 区 | 行范围 | 行数 | 内容 |
|---|---:|---:|---|
| 基础 | 70–228 | 159 | `is_az` / `only_letters` / `chi_squared` / `english_score` |
| 词表打分 | 229–333 | 105 | `_load_wordlist` / `word_coverage` / `nonletters_ok` / `modinv` |
| 凯撒 | 334–351 | 18 | `caesar_dec` / `caesar` |
| 维吉尼亚 | 352–512 | 161 | `index_of_coincidence` / `_best_caesar` / `_refine_key` / `vigcrack` |
| 仿射 | 513–553 | 41 | `affine_dec` / `affine_enc` / `affine`（312 种全爆破） |
| 单表替换（爬山） | 554–654 | 101 | `sub_hillclimb` |
| 培根 | 655–691 | 37 | 26 字母 / 24 字母两套表 |
| 栅栏 | 692–726 | 35 | `rail_dec` / `rail_enc` / `railfence` |
| 列置换 | 727–791 | 65 | `columnar_dec` / `_enc` / `_brute` |
| Atbash / A1Z26 | 792–894 | 103 | `atbash` 自反、`a1z26_decode` / `_encode` |
| 波利比奥斯 | 895–930 | 36 | 5×5 表 + 双向 |
| 普莱菲尔 | 931–1020 | 90 | `playfair_square` / `_pf_pos` / `_pf_strip_pad` / `playfair` |
| ADFGX | 1021–1084 | 64 | 方阵 + 双向 |
| 键盘错位 | 1085–1119 | 35 | `LAYOUTS` / `keyboard` / `keyboard_all` |
| T9 九宫格 | 1120–1169 | 50 | `t9_encode` / `t9` |
| 猪圈（符号替换） | 1170–1384 | 215 | `PIGPEN_SLOTS` / `PIGPEN_SHAPE` / `PIGPEN_EDGES` / `pigpen_segments` / `PIGPEN_VARIANTS`（9 个）/ `pigpen_encode` / `pigpen_decode` |
| auto | 1385–1437 | 53 | `auto` + `affine_enc_free` |
| CLI | 1438–1769 | 332 | `show_list` / `main` |

### 改代码时从哪下手

| 想做什么 | 去哪 |
|---|---|
| 加一个古典密码 | 新开一个 `# ---- 密码名` 区，照现有模式写 `xxx_dec` / `xxx_enc` / `xxx` 三个函数 |
| 破解不准 | `词表打分` 区的 `english_score` / `word_coverage` |
| 加进 auto | `auto`（L1387 附近），把新密码接进它的候选循环 |
| 加子命令 | `main`（L1498，258 行，手写参数解析） |

### 注意

- **词表加载顺序**：`$PUZZLE_WORDLIST` → `data/words.txt`（1582 词）→
  `../data/words.txt` → 系统词典（`/usr/share/dict/words` 等）。
  `_NO_WORDLIST_WARNED` 保证"没有词表"的警告只打一次。
- `sub_hillclimb` 是单表替换爬山破解，辅助函数是它的**嵌套函数**，所以
  "区里只有一个函数"是正常的，不是漏了。
- `playfair` 的 `_pf_strip_pad`：末尾填充的 x 无法自动判定（`taxa` / `exe`
  这类原文和填充同形），默认不清理，`--clean` 才去掉。

---

## 三、`hashcrypto.py`

1161 行 / 50 个顶层对象 / 8 个分区。

| 区 | 行范围 | 行数 | 内容 |
|---|---:|---:|---|
| 哈希识别 | 35–103 | 69 | `HASH_SIGNS` / `HASHLIB_ALGOS` / `identify` |
| 弱密码表 | 104–311 | 208 | `COMMON_PASSWORDS` / `candidates` / `md4` / `compute` / `crack` |
| XOR | 312–428 | 117 | `xor_single` / `xor_key` / `xor_repeat_detect` / 密钥推断 |
| AES / RC4 | 429–505 | 77 | `_pad` / `_unpad` / `aes_run` / `rc4` |
| RSA | 506–673 | 168 | `pollard_rho` / `factor` / `rsa_attack` / `_iroot` / `rsa_wiener` |
| JWT | 674–714 | 41 | `b64u_*` / `jwt_parse` / `jwt_crack` |
| CLI | 715–1013 | 299 | `die` / `main`（283 行） |
| 按格式穷举 | 1014–1161 | 148 | `MASK_SETS` / `parse_mask` / `chase_match` / `brute_force` |

### 改代码时从哪下手

| 想做什么 | 去哪 |
|---|---|
| 加一种哈希算法 | `HASHLIB_ALGOS`（能用 hashlib 的）+ `HASH_SIGNS`（靠长度/前缀识别的） |
| 破解慢 | `brute_force` / `_brute_worker`（多进程），掩码字符集在 `MASK_SETS` |
| 加 RSA 攻击 | `RSA` 区；`_iroot` 用二分 + `isqrt`，**别用 `x ** (1/k)`**（浮点精度不够） |
| 加子命令 | `main`（L729），283 行手写解析 |

### 注意

- **「弱密码表」这个区名偏窄**：它装的是完整的弱口令爆破流程（候选生成 →
  哈希计算 → 比对），不是只有一张表。`md4` 在这里是因为 OpenSSL 3 移除了
  md4，而 NTLM 破解需要它，只能自己实现。
- **「按格式穷举」是后加的功能**（hashcat 风格掩码）。它当初追加在文件末尾，
  把 `main` 挤进了自己区里（CLI 区只剩一个 `die`）；2026-11 已把 `main`
  移回 CLI 区，现在 CLI 是连续的 292 行。
- `crack` / `mask` / `xor` / `binwalk` 这些命令**只把答案留在 stdout**，
  进度和统计走 stderr——`hc crack xxx > out.txt` 才能拿到干净结果。

---

## 四、`stego.py`

1434 行 / 54 个顶层对象 / 7 个分区。

| 区 | 行范围 | 行数 | 内容 |
|---|---:|---:|---|
| 魔数 | 50–221 | 172 | `read` / `binwalk` / `_gif_end` / `tail_data` / `strings` / `mark_suspect` |
| 图片 | 222–463 | 242 | `open_img` / `lsb_extract` / `lsb_scan` / `png_chunks` / `png_text` / `exif_info` / `qr_scan` |
| ZIP | 464–546 | 83 | `zip_entries` / `zip_comment` / `zip_fake_encrypt` / `zip_extract` |
| 音频 | 547–572 | 26 | `spectrum`（要 `ffmpeg`） |
| 点阵网格（grid） | 573–1147 | **575** | `_png_canvas` / `canvas_of` / `_png_encode_rgb` / `inverted_copy` / `_otsu_split` / `_fit_axis` / `grid_read` / `print_grid` |
| 杂项 | 1148–1192 | 45 | `entropy` / `meta` / `hexdump` |
| CLI | 1193–1434 | 242 | `main`（233 行） |

### 改代码时从哪下手

| 想做什么 | 去哪 |
|---|---|
| 加一种容器格式的解析 | 照 `ZIP` 区那样，`xxx_entries` / `xxx_extract` 成对写 |
| grid 读错格子 | `_otsu_split`（阈值）+ `_fit_axis`（格宽）；两个都有实测依据，改动前先看注释 |
| LSB 看不出东西 | `lsb_scan`（按通道/位序枚举）+ `longest_printable`（挑最像人话的） |
| 加子命令 | `main`（L1202） |

### 注意

- **grid 区 575 行、9 个函数是一条完整链路**：纯标准库解 PNG → 二值化 →
  测格宽 → 读 0/1。`_png_canvas` / `canvas_of` 原本只被 `grid_read` 调用，
  所以放在 grid 区是对的。2026-11 给 `qr` 加反色重试时又在这里加了
  `_png_encode_rgb`（PNG 编码，和 `_png_canvas` 配成一对）和 `inverted_copy`
  （反转像素），于是 `canvas_of` 多了一个调用方。
  **编码器紧挨解码器是刻意的**——不要因为「它服务的是 qr」就把这两个单独
  挪去「图片」区，那样 PNG 的读和写会分处两章。
- `qr_scan` 原来误放在「音频」区（大概和 `spectrum` 一起加的），2026-11
  已归入「图片」。
- **纯标准库解 PNG**：位深 1/2/4/8/16，颜色类型 0/2/3/4/6，非隔行；
  装了 Pillow 才能读 JPEG/WebP/GIF。
- `_otsu_split` 的阈值取**平台中点**而不是左端——取左端会让紧贴低峰的格子
  翻面（实测 56 被阈值 55 判反，整串文字错一个字）。

---

## 五、`num.py`

227 行 / 13 个顶层对象 / **无分区**。

小文件，7 个函数线性排列，没到需要分区的规模：

| 函数 | 行 | 职责 |
|---|---:|---|
| `die` | 49 | 报错退出 |
| `to_base` | 54 | 整数 → 指定进制的字符串（2..36） |
| `fmt_num` | 69 | 加分组分隔符 / 前缀 |
| `parse_num` | 80 | 解析一个数，返回 `(值, 实际进制, 是否自动判定)` |
| `check_base` | 108 | 校验进制范围 |
| `show_all` | 118 | 一次列出 dec / hex / bin / oct |
| `main` | 128 | CLI（96 行） |

### 注意

- 这个脚本只做「**一个数换个写法**」（`ff` → 255），**不碰字节流**。
  `codec dec hex 48656c6c6f` → `Hello` 是 codec 的活。
- Python 的 `int(s, base)` 原生只支持 **2–36**。超过 36 的进制（base58 / base62）
  是编码不是进制，走 codec。
- 进制上限由 `check_base` 卡；`--pad` 补零用于点阵位流。

---

## 六、`ui.py` / `ui_params.py`

### `ui.py`（1851 行）

本地界面：`http.server` + **内嵌的 HTML/CSS/JS**（单文件，不需要前端构建）。

| 部分 | 位置 | 职责 |
|---|---|---|
| `run_action(payload)` | L505 | 唯一后端入口，按 `tab` 分发到各页 |
| `_encoding_names()` | L177 | 把注册表按「同一概念」去重（并查集），下拉框用 |
| `_run_mojibake` | L388 | mojibake 的四条通路（显式编码对 / best / deep / 普通） |
| `Handler._authed()` | L713 | 口令校验（`X-Token` 头 / `?token=`），不通过就 401 |
| `_is_local_host()` | L67 | 判断监听地址是不是只有本机能连（决定要不要强制口令） |
| `_run_stego` / `_run_num` / `_run_subcommand` | — | 各 tab 的执行 |
| 内嵌 JS `doRun()` | L1701 | 收集控件值 → POST `/api/run` |
| 内嵌 JS `buildSymbolPad` | L1412 | 按 slots 数据画可点的 SVG 方块网格（符号面板） |
| 内嵌 JS `updateSymPrev` | L1507 | 输入框下方的实时图形预览 |
| 内嵌 JS `updateSymOut` | L1537 | 结果框下方回显（符号直接画、字母按变体画回符号） |
| 内嵌 JS `pigpenLive` | L1572 | 实时双向换算，输入即出结果 |

### `ui_params.py`（489 行）

纯数据：`TABS`（5 个页签）+ `PARAMS`（每页每个动作的参数表）。

**`symbols` 控件类型**（目前只有猪圈用）：参数表里给 26 个槽位的图形数据，
前端画成可点的 SVG 方块，点击把近似字符写进**主输入框**而不是当成参数提交
（`paramValues()` 会显式跳过这个类型）。带 `"live": True` 的动作走实时双向
换算，输入一变就出结果，不用点「执行」。

形状数据从 `classic.PIGPEN_*` 导入，**不在这里重算** —— 两份形状定义迟早分叉，
分叉后界面点出来的符号跟命令行认的不是同一个字母，而且不报错。

**只在可选路径上 import codec**——为了取 `MOJIBAKE_ENCODINGS` / `MOJIBAKE_TARGETS`
那两份清单，不自己抄一份（抄了必然慢慢分叉，codec 加了编码界面永远选不到、
还不报错）。`except` 分支留了兜底清单，codec 不在同目录时仍能启动。
编码下拉的候选本身由调用方传进来（`_enc_choices(names)`）。

**注意 `_MOJIBAKE_TGT` 在 try/except 之后被改写过一次**：界面上的目标编码要
包含 `utf-8`，而 `MOJIBAKE_TARGETS` 是给自动跨编码枚举用的、不含它（UTF-8 在
`mojibake_rank` 里已是常驻假设）。别在 `codec` 侧加 utf-8 来"修"这个问题，
那会让自动枚举多跑一轮重复假设。

### ★ 最容易踩的坑：参数在 `params` 里

前端收集控件值时是**包一层**再发的：

```js
const payload = { tab, action, text, params: paramValues() };
```

所以后端必须从 `payload["params"]` 取。曾经有两处直接读顶层
（`payload["radix"]`、`payload["from"]`/`["to"]`/`["deep"]`/`["best"]`），
导致 `convert` 和 `mojibake` 的控件**选了等于没选**——这是 2026-11 才修的。

另一个坑：`paramValues()` 对 int 控件**无条件传值**（`deep` 默认 50 也会发），
所以判断"要不要走 `--deep`"只能看 `mode`，不能看 `deep` 有没有值。

### 改了内嵌 JS 之后

界面没有构建步骤，JS 是拼进 `ui.PAGE`（一个 `r"""…"""` 大字符串）的。
改完先把它抠出来再 check：

```bash
python3 -c "import re,ui;open('/tmp/_ui.js','w',encoding='utf-8').write(re.search(r'<script>(.*?)</script>',ui.PAGE,re.S).group(1))"
node --check /tmp/_ui.js
```

**整个 script 块 SyntaxError 时一个函数都不会执行**，症状往往是"按钮不见了"
而不是报错。
