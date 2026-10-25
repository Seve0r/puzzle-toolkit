---
name: hash-crypto
description: Use when dealing with hashes, modern crypto, or CTF crypto challenges — 哈希识别/爆破、MD5/SHA/NTLM、xor 异或、重复密钥 XOR、AES 加解密、RC4、RSA 分解与攻击、JWT 解析与密钥爆破、弱密码字典、加盐哈希（$1$/$5$/$6$/$2b$）。Provides hash type identification, dictionary cracking, single/repeating-key XOR recovery, and RSA attacks (Pollard rho, Fermat, Wiener, small-e).
---

# 哈希 / 现代密码

```bash
H=~/.dsh/skills/hash-crypto/scripts/hashcrypto.py
python3 $H <子命令> ...
```

| 子命令 | 用途 |
|---|---|
| `identify <hash>` | 猜哈希类型（长度 + 字符集 + `$1$`/`$6$`/`*XXXX` 前缀） |
| `hash <algo> <text>` | 计算，支持 md5/sha*/sha3/blake2/ntlm/mysql |
| `crack <hash> [--algo A] [--rules]` | 字典爆破（内置弱密码表 + 系统词表 + 变形规则） |
| `xor <hex> [--key HEX \| --key-str TEXT]` | 单字节全试 / 指定 key 异或 |
| `repeat-xor <file>` | **重复密钥 XOR**：汉明距离定长 + 逐列恢复 + 密钥修正 |
| `aes --key HEX [--iv HEX] [--mode cbc\|ecb\|ctr\|gcm]` | AES；加密输出 hex，解密吃 hex |
| `rc4 --key TEXT` | RC4 同理 |
| `rsa --n N --e E [--c C]` | 因式分解 → 求 d → 解密；会先试 Wiener |
| `jwt <token> [--crack]` | 解析 header/payload；按 `alg` 爆破 HS256/384/512 弱密钥 |

## 从文件读输入

以文件为输入时用 `-f`：

```bash
python3 $H identify -f hash.txt
python3 $H crack -f hash.txt
```

`repeat-xor` 是例外——它本来就吃文件路径：`python3 $H repeat-xor data.bin`。

## 参数与格式约定

**GCM 密文格式是 `ciphertext || tag`。** 加密时自动在末尾追加 16 字节 tag，
解密时取末尾 16 字节校验。GCM 是流模式、不做 PKCS#7 填充，所以只有
`cbc` / `ecb` 会去填充——早期版本对所有模式都 unpad，会把 `ctr` / `gcm`
明文尾巴上的字节误删。

**`xor` 的 `--key` 按十六进制解析，`--key-str` 才是文本 key。**
`--key abcd` 会被读成 `b"\xab\xcd"` 而不是 `b"abcd"`，因为 `abcd` 恰好全是
hex 字符。这种情况脚本会在 stderr 提示一句；本意是文本 key 就换 `--key-str`。

**`md4` 和 `md5(md5)` 现在都能破了。** 之前 `md4` 只出现在识别表里，
`compute` 走 `hashlib.new("md4")`，在 OpenSSL 3 上抛异常返回 None，于是
"识别得出来但永远破不了"。

**`jwt --crack` 按 token 头里的 `alg` 选哈希**，支持 HS256 / HS384 / HS512。
非 HS 系列（如 RS256）会明确报错，而不是给一个误导性的"没爆破出来"。

## 四个坑

**① `hashlib.new("md4")` 在 OpenSSL 3 上直接报错。**
NTLM 就是 MD4(UTF-16LE)，很多教程一句 `hashlib.new("md4", ...)` 就完事，
在 Ubuntu 22.04+ 上会抛 `unsupported hash type`。脚本里**手写了 MD4**，
`hash ntlm hello` → `066ddfd4ef0e9cd7c256fe77191ef43c`。

**② 同一个 32 位十六进制串可能是 md5 / md4 / NTLM / md5(md5)。**
`identify` 会把所有同形的都列出来，**必须靠爆破结果反证**——解出可读的是 md5，
解出来是乱码就换 ntlm 再试。别看到 32 位就认定 md5。

**③ 重复密钥 XOR 的密钥长度不能用"去倍数"筛。**
直觉是"6 位密钥时，12/18 的汉明距离一样好，应该排掉长的"。
但实测**反了**：真长度 6 的汉明距离经常排在它自己的约数 3 后面，
一按"去掉小候选的倍数"筛，就把真长度筛没了（`SECRET` 案例直接失败）。
正确做法：候选长度全试，用「明文可读性 − 0.15 × 密钥长度」排序——
约数解出来的明文只有一半对，分数自然低；倍数被长度惩罚压住。

**④ 逐列恢复的密钥会错一两个字节。**
某一列碰巧没区分度就错了，一个错字节会污染整段明文。必须做**多轮坐标下降**：
逐位试 256 个值，保留整体可读性最高的，扫到不再改进为止。
实测 5 组密钥（ICE/SECRET/KEY/night/XORKEY）能还原 4 组，剩下一个差一个字节。

## 加解密方向的约定

`aes`/`rc4` 统一规则：

```bash
CT=$(python3 $H aes --key 00112233... --iv 000102... --enc "hello")   # 加密 → 输出 hex
python3 $H aes --key 00112233... --iv 000102... "$CT"                 # 解密 → 吃 hex
```

加密时输入按**文本**理解，解密时输入先当 **hex**、不行再当 base64。
需要二进制输入输出时加 `--hex`。

## RSA

`rsa --n N --e E --c C` 会按顺序试：

1. **Wiener**（d 很小）
2. **直接分解**：先试小素数，再 Pollard rho，最后 Fermat（p、q 接近时有效）
3. **小 e 开方**：e ≤ 5 且 `m^e < n` 时 `iroot(c + k*n)` 爆破 k

已知 d 就直接 `--d D`。

## 没内建但常见的

- **coppersmith / 格攻击**：需要 sage，本地装不动，遇到小根问题去 online 工具
- **CRC32 逆向**：可以 `hash crc32`，但反推多项式需要专门的库
- **AES 密钥恢复**：那是密码分析，不是"解密"

## 效率提示

`crack` 不带 `--wordlist` 时会用内置 400+ 弱密码 **加** 一份英语词典。
词典按顺序取第一个可用的：`PUZZLE_WORDLIST` 环境变量 → 系统词典
`/usr/share/dict/words`（Linux / macOS，十万量级）→ 仓库内 `data/words.txt`
（约 1500 词，Windows 上的兜底）。系统词典里的 `English` 这类首字母大写的词
会额外生成全小写变体，因为真实密码多半写小写。

带 `--rules` 会生成大小写/加数字/反转变体，速度慢十倍左右，
先不带规则跑一遍再决定。真要爆破，`--wordlist rockyou.txt` 比任何词典都强。
