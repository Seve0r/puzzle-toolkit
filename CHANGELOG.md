# 更新日志

记录每次改动的要点。**加功能或修 bug 时先写进 `[未发布]`**，等提交时把
`[未发布]` 换成带日期的版本号，commit message 直接用这一段的要点。

分类固定用这五类：`新增` / `修复` / `变更` / `移除` / `文档`。

---

## [未发布]

### 修复

- `codec dec mojibake` / `--best` / `--deep`：乱码里含 `€` 时整行会错位一格。
  CP936 把单字节 `0x80` 定义成欧元符号 `€`，而 Python 的 `gbk` / `gb18030`
  codec 都不认这个单字节（`gb18030` 反而把 U+20AC 编成双字节 `A2E3`）。回编码时
  凭空多出一个字节，它之后的所有内容跟着错位——本来能无损还原的一行会被解成
  「丢?个亲生孩子」（正确是「一个亲生孩子」），损失率还被抬高、把正确假设挤掉。
  现在 GBK 系回编码改走 `_encode_back()`，遇到 `€` 手动还原成 `0x80`。
  实测同一行损失率 5.3% → 2.0%，`一个` / `一样` / `性问题` 全部恢复。

## [0.2.0] - 2026-10-24

### 新增

- `codec dec mojibake`：还原「UTF-8 被当成 GBK 读」的乱码（`浜哄彧` → `人只`）。
  枚举 gb18030 / gbk / big5 / shift_jis / euc-kr / latin-1 等 9 种假设，
  各自反编码回字节再按 UTF-8 解开，按 U+FFFD 损失率排序取最优。
- `codec dec mojibake --best`：**残缺数据专用**。谜题作者有时故意给缺字节的乱码，
  这时候不存在"更原始的来源"，`--best` 会强制输出最佳假设、把缺失处标成 `?`、
  并在 stderr 给出损失率。默认模式仍然严格（损失 >2% 直接报错），
  因为正常文本不该被误转成乱码。
- `codec mojibake_rank(s)`：打印所有假设的损失率排名，用来判断数据坏在哪一段。
- `codec dec mojibake --deep [N]`：多层乱码一步到位。反复还原，直到
  「正常文字占比」达到 N%（0~100，**默认 50**）为止。逐层打印损失率和可读率，
  并标出采信的是第几层。
  - 「正常文字占比」= CJK 字符里 GB2312 能编码的比例。只看 CJK、不算 ASCII，
    否则解过头变成 `?1?7` 噪音时反而会被算成高可读率，一路解到烂。
  - 可读率**不是单调上升**的（实测 33.7% → 36.4% → 88.5% → 0%），
    所以取的是全局最高那层，不是最后那层——解过头能自动退回。
  - 层级信息放在结果**之前**（走 stderr），空行隔开后才是结果。
    放后面时长文本会把两者推得很远，末尾那一大段说明反而抢视线。
- mojibake 的输出排版：最佳猜测另起一行、逐行缩进四格，避免结果本身带换行时
  把缩进冲掉、和报错文字挤在一起；`--best` 的损失率提示改到结果之后，
  并 flush stdout 保证顺序。
- `codec` mojibake 候选补上 `cp932` / `shift_jis_2004` / `shift_jisx0213`：
  严格的 `shift_jis` 编不出 `㈹`、半角片假名这类机种依存文字，会让整个日文假设
  被跳过（表现为「UTF-8 被当 Shift_JIS 读」的乱码完全解不出）。
  `cp932` 是 Shift_JIS 超集，能覆盖这些字符。

### 变更

- 添加 MIT 许可证（`LICENSE`）。
- README 移除「这是私有仓库」提示，改为面向公开仓库的表述。

### 文档

- README 新增「全部命令」一节：四个脚本共 50 条子命令的速查表 + 通用选项表。
- README 新增三节：「怎么喂数据」（`-f` 的四种必要场景 + 三条易错用法）、
  「数据完整性」（`�` 意味着原始字节缺失，不是脚本问题）、「更新」。
- README 「先跑哪个」补充 mojibake 和「混合编码需手工切分」两行。
- README 目录结构补充 `docs/` 文件索引和 `CHANGELOG.md`。
- `codec.py --help` 补上漏掉的 `grid` / `blocks` / `--best`；
  `stego.py --help` 补上漏掉的 `unzip` / `hexdump`。

---

## [0.1.0] - 2026-10-24

首个可用版本。

### 新增

- `codec.py`：编码识别与解码。支持 base16/32/58/62/64/85/91、hex、二进制、十进制、
  八进制、URL、HTML 实体、Unicode 转义、Quoted-Printable、ROT13/47、Atbash、摩斯、
  盲文、gzip/zlib/bz2、UTF-16/32、GBK。`auto` 递归剥皮，默认 3 层。
- `classic.py`：凯撒、维吉尼亚、仿射、单表替换、培根、栅栏、列置换、Atbash、A1Z26、
  波利比奥斯、普莱菲尔、ADFGX、键盘错位、T9。带密钥的加密/解密，无密钥的自动爆破。
- `hashcrypto.py`：哈希识别与字典爆破、单字节/重复密钥异或、AES、RC4、RSA、JWT。
- `stego.py`：binwalk、文件尾附加数据、strings、LSB、PNG 块、ZIP 结构、EXIF、
  二维码、音频频谱。
- `data/words.txt`：内置 1500 个常用英语词，让 Windows 上也能跑单表替换和字典爆破。

### 修复

`classic.py`

- `caesar --key N` 必定崩溃：`--key` 拿到的是字符串，却被当整数取负。
- `vigcrack` 末尾两行是不可达的死代码。
- `a1z26` 把空格分隔的 `1 12 3` 贪心拼成 `22`，解出 `vc` 而不是 `alc`。
- `playfair` 加解密不互逆：加密时为拆重复字母或补齐奇数长度插入的 `x`，解密后从不还原。

`codec.py`

- `read_input` 靠「调用方多传一个参数给它吃掉」的隐式约定工作，调用方一改就错位，改成显式约定。
- `enc hex -f` 输出的不是文件真实字节（文件先被 `as_text` 用 U+FFFD 污染过）。
- 盲文数字模式从未生效：`"abcdefghij"[ord(letter)-97]` 恒等于字母本身，数字全被当字母输出。
- `auto` 用 `hash(text[:200])` 做缓存键，前缀相同的两个长文本会共享对方的结果。

`hashcrypto.py`

- AES GCM 解密必然失败（没传 tag）；且 `ctr`/`gcm` 被错误地做 PKCS#7 去填充，吃掉了明文尾巴。
- `_iroot` 用浮点开方：50 位就解错，200 位直接溢出。改成整数二分。
- `md4` 和 `md5(md5)` 识别得出来却永远破不了（`hashlib.new("md4")` 在 OpenSSL 3 上抛异常）。
- `jwt --crack` 硬编码 SHA256，HS384 / HS512 的 token 永远爆不出来。
- `xor --key` 把纯 hex 字符的文本 key 静默当十六进制解析（新增 `--key-str`）。
- Fermat 分解无条件下限 10 万次，p/q 不接近时纯烧 CPU。改成 1 秒时间上限。

`stego.py`

- `qr_scan(path, use_all or True)` 恒为 True，`--all` 形同虚设，而且每次都白跑两轮放大识别。
- `binwalk` 的 `BM` / `MZ` 两字节魔数误报极高（1MB 文件里平均撞十几次），加合理性校验。
- `strings -n N` 对 N<4 无效：正则写死 `{4,}`，参数看起来生效其实没用。
- GIF trailer 用 `rfind(b"\x3b")` 找，`0x3B` 就是 `;`，图像数据里常见，偏移会错。改成解析块结构。
- `unzip` 的路径防护挡不住 Windows 的 `C:\foo`（zip-slip），加 `realpath` 越界校验。
- 硬编码 `/usr/bin/zbarimg` 和 `/tmp/*.png`，改为 `shutil.which` 和 `tempfile`。

### 变更

- 词表查找改为多路径：`PUZZLE_WORDLIST` 环境变量 → 仓库内 `data/words.txt` →
  系统词典。Windows 上不再因为缺 `/usr/share/dict` 而失效。
  找不到任何词表时会在 stderr 明确提示降级，不再静默变成纯 bigram。
- `playfair` 默认不做填充清理（保持严格互逆），需要干净结果时加 `--clean`。
  自动清理会误伤原文本身含 `xax` 的词（如 `taxa`），所以不设为默认。
- `hashcrypto` 的字典爆破对系统词典里首字母大写的词额外生成全小写变体，
  因为真实密码多半写小写（`English` vs `english`）。
