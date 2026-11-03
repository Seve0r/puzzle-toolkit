# 提示词：请帮我生成一份命令行工具的测试数据集

> 用法：把整份文件内容（从下一行「你是测试工程师」开始）复制给另一个 AI。

---

你是测试工程师。请为一个**纯 Python 标准库**的命令行工具包生成一份**自动化测试数据集**，
用于全量回归测试。你拿不到源码，下面会给你完整的命令清单和已知行为，**请严格按此生成**。

## 一、这个工具包是什么

`puzzle-toolkit` —— 解谜（ARG / CTF）用的命令行工具集，5 个独立脚本，各自 `python3 <脚本> <命令> [参数]`：

| 脚本 | 职责 |
|---|---|
| `codec.py` | 编码识别与解码（base 家族 / 进制 / 摩斯 / 盲文 / 编码转换 / 乱码还原） |
| `classic.py` | 古典密码（凯撒 / 维吉尼亚 / 仿射 / 培根 / 栅栏 / 列置换 / 普莱菲尔 / ADFGX / 键盘错位 / T9） |
| `hashcrypto.py` | 哈希识别与爆破 / XOR / AES / RC4 / RSA / JWT |
| `stego.py` | 文件隐物取证（binwalk / LSB / PNG / ZIP / 频谱 / 二维码 / 点阵图） |
| `num.py` | 进制转换（数值视角，不碰字节流） |

## 二、环境与硬性约束（违反 = 用例跑不起来，请务必遵守）

1. **只用 Python 标准库**。不要假设装了 `pycryptodome` / `numpy` / `pillow` 之类。
2. **禁止任何联网用例**。
3. **外部工具可能不存在**：`ffmpeg`（stego 的 `spec`）、`zbarimg`（stego 的 `qr`）
   属于可选依赖。涉及它们的用例必须标 `"requires": ["ffmpeg"]` 或 `["zbarimg"]`，
   我们会在没装时跳过。**不要**把它们混进普通用例。
4. **不要生成依赖大文件的用例**（>100 KB）。需要文件输入时用下面「fixtures」机制，
   内容控制在 1 KB 以内。
5. **不要用时间、随机数、临时路径**作为期望值的一部分。
6. 期望输出必须是**你能确定性算出来的**。不确定就标 `"expect": {"unknown": "原因"}`，
   **绝对不要凭印象写**。宁可少一条，不要错一条。

## 三、完整命令清单

### `codec.py`

```
子命令：
  auto   <text>                    自动识别编码并递归剥皮
  brute  <text>                    每种编码都试一遍，按可读性排序
  dec    <enc> <text>              用指定编码解码
  enc    <enc> <text>              用指定编码编码
  list                             列出所有支持的编码名
  grid   <text> [--rows N] [--cols N] [--width N]     切矩阵枚举读法
  blocks <text> [-w 宽] [-r 进制]  定长块按进制转字节（如 -w 2 -r 36）
  convert <text> [-r 进制] [-e 编码]
                                   进制 × 字符编码 两个维度分开指定
                                   -r: 2/8/10/16/36（默认 16）
                                   -e: utf-8/gbk/gb18030/big5/shift_jis/ascii/latin-1/auto

通用选项：
  -f, --file <path>   从文件读输入
  -q, --quiet         只输出结果，不要解释
  --depth N           auto 的递归深度（默认 3）
  --best              配合 dec mojibake：数据残缺时强制输出最佳猜测，缺失处标 ?
  --deep [N]          配合 dec mojibake：反复还原直到正常文字占比 >= N%
  --from <enc>        配合 dec mojibake：指定源编码
  --to <enc>          配合 dec mojibake：指定目标编码
  --katakana          配合 dec wabun：输出片假名
```

### `classic.py`

```
  caesar    [--key N] <text>                 不给 key 就 26 种全爆破
  vigenere  --key KEY <text>                 加/解密用 --enc
  vigcrack  <text>                            维吉尼亚无密钥破解
  affine    [--a N --b N] <text>              不给参数就 312 种全爆破
  sub       <text>                            单表替换爬山破解（<20 字母会报错）
  bacon     [--old] <text>                    26 字母 / 24 字母两套
  railfence [--rails N] <text>                不给栏数就全爆破
  columnar  [--key KEY] <text>
  atbash    <text>
  a1z26     [--dec] <text>
  polybius  [--dec] <text>
  playfair  --key KEY <text>                  --enc 加密，--clean 去填充 x
  adfgx     --key KEY [--trans KEY] <text>
  keyboard  [--layout qwerty|dvorak|azerty] <text>
  t9        <digits>                          列出所有可能
  auto      <text>                            全部跑一遍按契合度排序

通用：--enc 编码方向（默认解码） / -q / -f FILE / -n N（只显示前 N 个候选，默认 10）
```

### `hashcrypto.py`

```
  identify <hash>                             猜哈希类型
  hash <algo> <text>                          计算（md5/sha1/sha256/sha512/...）
  crack <hash> [--algo A] [--wordlist F] [--rules]
  xor <data> [--key HEX | --key-str TEXT]     单字节全试 / 指定 key / 多字节自动
  repeat-xor <file>
  aes --key HEX [--iv HEX] [--mode cbc|ecb|ctr|gcm] <base64|hex>
  rc4 --key TEXT <data>
  rsa --n N --e E [--c C] [--d D]
  jwt <token>                                 --crack 爆破 HS256
  list

通用：--hex（输入是 hex）/ -f FILE / -q
```

### `stego.py`

```
  binwalk <file>         扫描内嵌文件特征
  tail <file>            检测文件尾附加数据
  strings <file> [-n 6]  可打印字符串 + 标出可疑项
  lsb <image>            逐通道 LSB 提取
  lsbscan <image>        更彻底（1~3 位、6 种通道组合）
  exif <image>           读元数据
  pngchunks <png>        列 PNG 块
  zipinfo <zip>          列条目/注释/伪加密
  unzip <zip> [--out DIR]
  hexdump <file> [-l N]
  qr <image>             需要 zbarimg
  spec <audio> --out a.png   需要 ffmpeg
  grid <image>           点阵图切格子输出 0/1
  meta <file>            类型 + 尺寸 + 熵

通用：-q
```

### `num.py`

```
  num.py <数> [...]                列出 dec/hex/bin/oct
  num.py <数> --to N               只输出指定进制
  num.py <数> --from N --to M

选项：--from N / --to N（2..36） / -f FILE（F 给 - 表示 stdin） /
      --upper / --prefix / --pad N / -q
```

## 四、数据集格式

输出**一个 JSON 文件**，顶层是对象：

```json
{
  "meta": {
    "generator": "你给自己起的名字",
    "tool": "puzzle-toolkit",
    "schema_version": 1,
    "count": 0
  },
  "fixtures": [],
  "cases": []
}
```

### `fixtures`（可选，需要文件输入的用例才用）

```json
{"name": "hello.txt", "content_b64": "aGVsbG8K"}
```

测试脚本会把这些文件写到临时目录，用例里的 `-f hello.txt` 用**裸文件名**引用。

### `cases`（每个元素）

```json
{
  "id": "codec-auto-001",
  "script": "codec.py",
  "args": ["auto", "S1VWRVIgTEFOR1VBR0U="],
  "stdin": null,
  "expect": {
    "exit": 0,
    "stdout": "KUVER LANGUAGE",
    "stderr_contains": ["路径：base64"]
  },
  "tags": ["basic", "codec", "base64"],
  "note": "base64 单层"
}
```

字段约定（**严格执行**）：

| 字段 | 说明 |
|---|---|
| `id` | 唯一，格式 `<脚本>-<类别>-<三位序号>` |
| `script` | 必须是上表 5 个文件名之一 |
| `args` | 字符串数组，**逐个参数**列出，不要拼成一个字符串 |
| `stdin` | 字符串或 `null`；用它给 `-f -` 或管道输入 |
| `expect.exit` | 期望退出码，成功 0，失败非 0 |
| `expect.stdout` | **精确匹配**：测试脚本会去掉末尾换行后逐字符比较 |
| `expect.stdout_contains` | 替代方案：只检查包含这些子串（输出不稳定时用） |
| `expect.stderr_contains` | 只检查 stderr 包含这些子串（错误提示、报告行） |
| `requires` | 可选，外部依赖，如 `["ffmpeg"]` |
| `tags` | 至少含一个类别标签：`basic` / `edge` / `error` / `roundtrip` |
| `note` | 一句话说明这条在测什么 |

**`stdout` 和 `stdout_contains` 二选一，不要同时给。**

## 五、覆盖要求

1. **每个子命令至少 1 条**（含 `list`、`--help` 这类）。
2. **每个脚本至少 40 条**，五个脚本合计不少于 200 条。
3. 类别分布大致：`basic` 50%、`edge` 20%、`error` 15%、`roundtrip` 15%。
4. **`error` 类必须有**：非法字符、超范围、缺参数、输入太短等，且 `exit` 非 0。
5. **编码类必须覆盖中/日/韩文**，不要只有 ASCII。
6. **`roundtrip`**：`enc` 出来的东西喂给 `dec` 能回来。这类写成两条用例
   （一条 enc 检查输出，一条 dec 用**你算出的** enc 结果作输入），或直接标
   `"roundtrip": ["enc", "dec"]` 让我们做链式测试。
7. `classic` 的每个密码至少 `dec` 一条；能编码的（`--enc`）再加一条。

## 六、已知行为怪癖（**决定你的期望值怎么写，务必读**）

这些是实测确认过的，写错期望值会导致批量误报：

1. **`codec.py` 的 `enc` 对二进制类不可用于 stdout 比对**。
   `gzip` / `utf16` / `utf32` / `uu` 的编码结果是「latin-1 承载的二进制」，经 stdout
   会按 UTF-8 写坏。**只测它们的 `dec` 方向**（用 hex 文本作输入），不要测 `enc`。

2. **纯 ASCII 的编码报告写「ASCII（与编码无关）」**，不会写 `UTF-8`。
   例如 `codec.py convert 2W33342T -r 36` 的 stderr 里有：
   `字符编码：auto → ascii`，以及一行「字节全部 < 128，是纯 ASCII」。

3. **`convert` 的报错顺序是：先字符集，再长度，再范围**。
   `codec.py convert '41g 42' -r 16` → stderr `含十六进制以外的字符：'g'`（不是"位数是奇数"）。

4. **`base36` 和 `block36` 是两个不同的编码**：
   - `base36`：整串当一个大整数
   - `block36`：每两位一个字节。`2W33342T` → `hope`
   别混。

5. **`dec mojibake` 输入少于 3 个字符会报错**（"不足以判断是不是乱码"）。

6. **`classic.py` 的输出普遍带格式前缀**，不是裸结果：
   `classic.py caesar KHOOR --shift 3` → `  k=3   HELLO`（两个空格 + `k=` + 三个空格）。
   `--quiet` 也只去掉部分提示。**期望值必须包含这些前缀字符**。

7. **`hashcrypto.py` 的 `crack`/`xor` 只把答案留 stdout**，进度走 stderr。
   所以 `stdout` 期望是干净的答案。

8. **`num.py` 会吃掉前导零**：`num.py 0x00ff` 和 `num.py 0xff` 是同一个数。
   要测补零得用 `--pad`，期望值算作 `"ff"` 而不是 `"00ff"`。

9. **`stego.py` 的 `meta` 输出是「两个前导空格 + 标签 + 对齐空格 + 值」**，实测形如
   `  file         README.md`、`  size         19107`、`  type         未知`。
   注意开头**有两个空格**，标签后的空格数也是固定的。字段值可能是"未知"（取决于文件），
   所以这类建议用 `stdout_contains` 而不是精确 `stdout`。

10. **`codec.py auto` 的 stderr 含得分（如 `得分：185.0`）**，可能随实现微调变化。
    对 auto 只检查 `stdout`（结果）和 `stderr_contains`（`路径：` 这类关键词），
    **不要**检查完整 stderr。

11. **`playfair --clean` 才会去掉末尾填充的 x**，默认不去。原文本来就含 `x` 时
    无法自动判定，别写"默认去填充"的期望。

12. **和文摩斯（`dec wabun`）默认输出平假名，且没有小假名**：
   `enc wabun ガッコウ` 再 `dec` 回来是 `がつこう`（假名变小写、ッ→ツ）——
   这是体系限制，不是 bug。要看片假名得加 `--katakana`，那时是 `ガツコウ`。

## 六之二、输出格式速查（**写期望值前先看这个**）

上一版数据集 200 条里有 90 条期望值写错，**七成是因为不知道输出长什么样**。
下面是从实际运行里抄下来的形态，照这个写：

| 命令 | stdout 形态 |
|---|---|
| `codec.py auto` / `dec` / `enc` / `convert` | 纯结果，一行 |
| `codec.py list` | `名字` + 对齐空格 + `enc` 标记（有编码器的才有） |
| `codec.py blocks` | **三行报告**：`bytes: [104, 111, 112, 101]` / `ascii: hope` / `utf-8: hope` |
| `codec.py brute` | 首行「对 'xxx' 尝试所有编码：」，之后每行 `  名字   得分   结果` |
| `codec.py grid` | 纯 0/1 点阵，**不带行号** |
| `classic.py <密码>` | 常带格式前缀：`  k=3   HELLO`（两空格 + k= + 三空格） |
| `classic.py columnar` | `  key=xxx   得分   结果` 多行 |
| `classic.py auto` | 首行「全部手法尝试（按英文契合度）：」+ 排名行 |
| `classic.py list` | 子命令清单 |
| `hashcrypto.py identify` | `  md5            32 位十六进制` |
| `hashcrypto.py hash` | 纯 hex，一行 |
| `hashcrypto.py crack` | 纯明文，一行（进度走 stderr） |
| `hashcrypto.py xor` | `  key=0xNN   得分   b'结果'` |
| `hashcrypto.py list` | `  名字   位数   说明` |
| `stego.py meta` | **两个前导空格** + 标签 + 对齐空格 + 值：`  file         x.txt` |
| `stego.py hexdump` | `偏移  hex  \|ascii\|` |
| `stego.py binwalk` / `zipinfo` | 表格 / 清单 |
| `num.py <数>` | 四行：`dec   255` / `hex   ff` / `bin   11111111` / `oct   377` |
| `num.py <数> --to N` | 纯一个值 |

## 六之三、上一版数据集栽过的 7 个坑（新加的，务必避开）

1. **参数解析是手写的，不是 argparse。** 所以**根本不存在** `usage:` /
   `error:` / `invalid choice` 这些输出。真实报错长这样：
   - `失败：含十六进制以外的字符：'g'`（codec，走 **stderr**）
   - `出错：文本太短（至少 20 个字母），单表替换破解不可靠`（classic，走 **stdout**）
   - `--to 进制必须是 2..36。…`（num，走 stderr）
   **失败退出码统一是 1**（少数参数缺失是 2），不要写 argparse 的 2。

2. **`classic.py` 解出来的明文是小写**：`a1z26 --dec 8 5 12 12 15` → `hello`。

3. **`codec.py blocks` 不是纯结果**，是三行报告；且 `-q` 对它无效。

4. **含得分/评估的输出不要用精确 `stdout`**：`codec brute`、`classic auto` /
   `columnar`、`hashcrypto xor` 里有 `125.0`、`108.0` 这类分数，会随实现微调
   变化。用 `stdout_contains` 断言稳定的部分（编码名、结果）。

5. **子命令 `--help` 不一定有输出**：`classic.py bacon --help` / `polybius --help` /
   `t9 --help` 是**空输出 + exit 0**（只有部分子命令写了说明）。

6. **fixture 必须是真能用的文件**。上一版手搓的 PNG 里 IDAT 块 CRC 算错了，
   `zlib.decompress` 直接报 `incorrect data check`，stego 全线 "broken data
   stream"——**四条用例集体误报**。生成二进制 fixture 后务必自己解一遍。

7. **不要凭想象编密文**。上一版写 `playfair --key A --enc HELLO` 期望 `KCMMNY`，
   实际是 `kcnvmp`。要么用 Python 自己算，要么标 unknown。

## 七、验收标准（你自己检查一遍再交）

- [ ] JSON 能被 `json.load` 解析，无尾逗号
- [ ] `id` 全局唯一
- [ ] 每条都有 `id` / `script` / `args` / `expect` / `tags` / `note`
- [ ] `script` 只出现那 5 个文件名
- [ ] 所有 `expect` 里没有 `TODO` / `???` / 你自己的猜测
- [ ] `error` 类的 `exit` 都不是 0
- [ ] 每条的期望值你都能说出是怎么算出来的（写在 `note` 里更好）
- [ ] 没有联网、没有大文件、外部依赖都标了 `requires`

## 八、最后

生成完成后，请附一段简短说明：
- 总共多少条，各类别多少
- 哪几条你自己不确定（列 `id`），让我们重点核对
- 你觉得还缺哪类用例（但没生成）

**再次强调：不确定的期望值宁可不写，标 `"unknown"` 并说明原因。一份有 20 条确定的用例，
比一份 200 条里有 50 条错的用例有用得多。**
