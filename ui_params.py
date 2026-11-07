# -*- coding: utf-8 -*-
"""界面参数表：每个「有选项」的功能在这里声明自己要什么参数。

为什么单独一个文件
------------------
codec 的 mojibake 就有 `--best` / `--deep` / `--from` / `--to` 四个开关，
classic 的 vigenere 要密钥、adfgx 要两个密钥、hashcrypto 的 rsa 要 n/e/c。
如果每加一个功能就去界面代码里硬塞一组控件，界面会越来越难改。

写成声明式表格之后：**加功能只改这里，界面代码一行不用动**。
前端拿到这张表，按 type 生成对应控件。

字段
----
key        提交给后端的字段名
type       choice / int / text / check
label      界面上显示的标签
default    默认值（不填 = 不提交该字段）
choices    type=choice 时的 [(值, 显示名), ...]
show_if    只在另一个参数等于某值时才显示，如 {"mode": "deep"}
hint       控件旁边的一行小字
suffix     type=int 时的单位后缀

注意
----
这里是**界面语言**，不是命令行参数的镜像。比如命令行有 `--best` / `--deep`
两个互斥开关，界面上合成一个 `mode` 三选一更清楚，后端再拆回对应调用。
"""


# ---------------------------------------------------------------------------
# 四个选项卡。codec 的「功能」就是编码名（由 codec.py 的注册表来），
# 其余三个的「功能」是脚本的子命令，得在这里列。
#
#   input = "text"  普通文本框（classic / hashcrypto）
#   input = "file"  只能选文件（stego 要原始字节，当文本读会损坏数据）
# ---------------------------------------------------------------------------
TABS = [
    {"id": "codec", "label": "编码", "input": "text", "kind": "encoding"},
    {
        "id": "classic", "label": "古典密码", "input": "text",
        "actions": [
            {"name": "caesar", "label": "凯撒（不给位移就全爆破）"},
            {"name": "vigenere", "label": "维吉尼亚"},
            {"name": "vigcrack", "label": "维吉尼亚 · 无密钥破解"},
            {"name": "affine", "label": "仿射（不给参数就全爆破）"},
            {"name": "sub", "label": "单表替换 · 爬山法破解"},
            {"name": "bacon", "label": "培根"},
            {"name": "railfence", "label": "栅栏"},
            {"name": "columnar", "label": "列置换"},
            {"name": "atbash", "label": "Atbash"},
            {"name": "a1z26", "label": "A1Z26"},
            {"name": "polybius", "label": "波利比奥斯"},
            {"name": "playfair", "label": "普莱菲尔"},
            {"name": "adfgx", "label": "ADFGX"},
            {"name": "keyboard", "label": "键盘错位"},
            {"name": "t9", "label": "手机九宫格 T9"},
            {"name": "auto", "label": "全部试一遍"},
        ],
    },
    {
        "id": "hashcrypto", "label": "哈希 / 现代密码", "input": "text",
        "actions": [
            {"name": "identify", "label": "识别哈希类型"},
            {"name": "hash", "label": "计算哈希（明文 → 哈希）"},
            {"name": "crack", "label": "字典爆破"},
            {"name": "xor", "label": "XOR（单字节 / 指定密钥）"},
            {"name": "repeat-xor", "label": "重复密钥 XOR 自动检测"},
            {"name": "aes", "label": "AES 加解密"},
            {"name": "rc4", "label": "RC4"},
            {"name": "rsa", "label": "RSA 解密与攻击"},
            {"name": "jwt", "label": "JWT 解析 / 爆破"},
            {"name": "mask", "label": "按格式穷举（掩码爆破）"},
        ],
    },
    {
        "id": "stego", "label": "隐写取证", "input": "file",
        "actions": [
            {"name": "binwalk", "label": "扫描内嵌文件"},
            {"name": "tail", "label": "文件尾附加数据"},
            {"name": "strings", "label": "可打印字符串"},
            {"name": "lsb", "label": "LSB 逐通道提取"},
            {"name": "lsbscan", "label": "LSB 彻底扫描"},
            {"name": "exif", "label": "元数据"},
            {"name": "pngchunks", "label": "PNG 块"},
            {"name": "zipinfo", "label": "ZIP 结构"},
            {"name": "unzip", "label": "解压"},
            {"name": "hexdump", "label": "十六进制查看"},
            {"name": "qr", "label": "二维码 / 条码"},
            {"name": "spec", "label": "音频频谱图"},
            {"name": "grid", "label": "点阵图读 bit 流"},
            {"name": "meta", "label": "文件类型与熵"},
        ],
    },
    # 进制面板：输入一个数，直接列出它 2..36 的全部写法（不走「结果」文本框，
    # 而是每行一个进制的独立输入框，方便单独复制某一项）
    {
        "id": "num", "label": "进制", "input": "num",
        "actions": [{"name": "convert", "label": "转换"}],
    },
]


# ---------------------------------------------------------------------------
# 各功能的参数表，键是 "选项卡/功能"（codec 直接用编码名）。
# ---------------------------------------------------------------------------

# 乱码还原的「源编码 / 目标编码」清单直接取自 codec，不在这里再抄一份 ——
# 抄一份的下场是两边慢慢分叉：codec 里加了 cp1251，界面下拉里没有，用户
# 永远选不到，而且不会报错。
try:
    import codec as _codec
    _MOJIBAKE_SRC = list(_codec.MOJIBAKE_ENCODINGS)
    _MOJIBAKE_TGT = list(_codec.MOJIBAKE_TARGETS)
except Exception:                       # codec 不在同目录时给个能跑的兜底
    _MOJIBAKE_SRC = ["gb18030", "gbk", "shift_jis", "big5", "euc-kr"]
    _MOJIBAKE_TGT = ["utf-8", "gb18030", "gbk", "shift_jis", "big5"]

# 界面上的「目标编码」必须包含 utf-8，而 MOJIBAKE_TARGETS 里没有它 ——
# 那个常量是给**自动跨编码枚举**用的：mojibake_rank 已经把 UTF-8 当常驻
# 假设跑过一遍，不必在 src × tgt 里再枚举一次。
# 但界面上「源 gbk → 目标 utf-8」恰恰是最常用的一种显式组合（UTF-8 文本
# 被当 GBK 读，也就是 浜哄彧鑳界湅 → 人只能看），下拉里没有就等于这个
# 组合在界面上压根用不了 —— 而 CLI 的 `--to utf-8` 一直是支持的。
# 放在 try/except 之后统一补，两条路径（真实 codec / 兜底清单）都覆盖。
_MOJIBAKE_TGT = ["utf-8"] + [e for e in _MOJIBAKE_TGT if e != "utf-8"]

# 下拉里显示的友好名。没列到的就直接显示编码名本身。
_ENC_LABEL = {
    "gb18030": "gb18030（GBK 超集）",
    "gbk": "gbk（简体中文）",
    "cp932": "cp932（Windows 日文）",
    "shift_jis": "shift_jis（日文）",
    "shift_jis_2004": "shift_jis_2004（日文新字体）",
    "shift_jisx0213": "shift_jisx0213",
    "big5": "big5（繁体中文）",
    "euc-kr": "euc-kr（韩文）",
    "euc-jp": "euc-jp（日文）",
    "iso2022_jp": "iso2022_jp（日文）",
    "latin-1": "latin-1（西欧，一字符一字节）",
    "cp1252": "cp1252（Windows 西欧）",
    "cp1251": "cp1251（西里尔/俄文）",
    "iso-8859-2": "iso-8859-2（中东欧）",
    "utf-8": "utf-8",
}


def _enc_choices(names):
    """第一项是空值 = 不指定（走自动/默认），其余按 codec 的顺序排。"""
    return [("", "不指定（自动）")] + [
        (n, _ENC_LABEL.get(n, n)) for n in names]



# convert：自己指定「字符编码 + 进制」。这两个维度是正交的——
# 现有的 dec/bin/hex/oct/block36 其实都是「某进制 + UTF-8」的快捷方式。
_PARAMS_CONVERT = [
    {"key": "encoding", "type": "choice", "label": "字符编码", "default": "auto",
     "choices": [
         ("auto", "自动（UTF-8 → GBK → GB18030 → Big5 → Shift_JIS 依次试）"),
         ("utf-8", "UTF-8"), ("gbk", "GBK"), ("gb18030", "GB18030"),
         ("big5", "Big5（繁体）"), ("shift_jis", "Shift_JIS（日文）"),
         ("ascii", "ASCII（只要 0–127）"), ("latin-1", "Latin-1（一字符一字节）"),
     ],
     "hint": "字节按哪种编码变成文字。同一批字节换个编码可能是另一句话；"
             "auto 只是「挑一个能解的」，不代表只有这一种读法"},
    {"key": "radix", "type": "choice", "label": "进制", "default": "16",
     "choices": [
         ("16", "十六进制 · 两位一字节（可带空格）"),
         ("10", "十进制 · 一个数一字节（要空格分隔）"),
         ("8", "八进制 · 一个数一字节（要空格分隔）"),
         ("2", "二进制 · 八位一字节"),
         ("36", "base36 · 两位一字节"),
     ],
     "hint": "字节怎么写出来的"},
]

_BASE_NAMES = {2: "二进制", 8: "八进制", 10: "十进制", 16: "十六进制"}
_NUM_BASES = [("", "自动识别")] + [
    (str(b), _BASE_NAMES.get(b, "%d 进制" % b)) for b in range(2, 37)
]

PARAMS = {
    "mojibake": [
        {
            "key": "mode", "type": "choice", "label": "还原模式",
            "default": "normal",
            "choices": [
                ("normal", "普通（损失 ≤2% 才认）"),
                ("best", "最佳猜测 --best"),
                ("deep", "多层还原 --deep"),
            ],
        },
        {
            "key": "deep", "type": "int", "label": "可读率阈值",
            "default": 50, "min": 0, "max": 100, "suffix": "%",
            "show_if": {"mode": "deep"},
            "hint": "反复剥皮直到正常文字占比达到这个值",
        },
        {
            "key": "from", "type": "choice", "label": "源编码", "default": "",
            "choices": _enc_choices(_MOJIBAKE_SRC),
            "hint": "当初「把字节解成乱码」用的那个编码。留空则自动判断",
        },
        {
            "key": "to", "type": "choice", "label": "目标编码", "default": "",
            "choices": _enc_choices(_MOJIBAKE_TGT),
            "hint": "当初应该用来解的那一个。两个都选就不猜了",
        },
    ],
    # ---------------- classic ----------------
    "classic/caesar": [
        {"key": "key", "type": "int", "label": "位移", "min": -25, "max": 25,
         "hint": "不填就 26 种全爆破"},
    ],
    "classic/vigenere": [
        {"key": "key", "type": "text", "label": "密钥", "placeholder": "如 LIME"},
    ],
    "classic/affine": [
        {"key": "a", "type": "int", "label": "a", "hint": "与 26 互质；不填就 312 种全爆破"},
        {"key": "b", "type": "int", "label": "b", "hint": "与 a 一起决定位移量"},
    ],
    "classic/bacon": [
        {"key": "old", "type": "check", "label": "旧式 24 字母（I/J、U/V 合并）"},
    ],
    "classic/railfence": [
        {"key": "rails", "type": "int", "label": "栏数", "hint": "不填就全爆破"},
    ],
    "classic/columnar": [
        {"key": "key", "type": "text", "label": "关键词", "hint": "不填就按长度爆破"},
    ],
    "classic/playfair": [
        {"key": "key", "type": "text", "label": "关键词", "placeholder": "如 MONARCHY"},
        {"key": "enc", "type": "check", "label": "加密方向"},
        {"key": "clean", "type": "check", "label": "去掉填充的 X"},
    ],
    "classic/adfgx": [
        {"key": "key", "type": "text", "label": "方阵关键词", "placeholder": "如 BALLOON"},
        {"key": "trans", "type": "text", "label": "转置关键词", "placeholder": "如 CIPHER"},
    ],
    "classic/keyboard": [
        {"key": "layout", "type": "choice", "label": "布局", "default": "qwerty",
         "choices": [("qwerty", "QWERTY"), ("dvorak", "Dvorak"), ("azerty", "AZERTY")]},
        {"key": "shift", "type": "choice", "label": "方向", "default": "-1",
         "choices": [("-1", "往左还原"), ("1", "往右还原")]},
    ],

    # ---------------- hashcrypto ----------------
    # 正向算哈希：给明文，出 md5/sha*/ntlm…
    "hashcrypto/hash": [
        {"key": "algo", "type": "choice", "label": "算法", "default": "md5",
         "choices": [
             ("md5", "md5（32 位 hex）"), ("sha1", "sha1（40 位）"),
             ("sha256", "sha256（64 位）"), ("sha512", "sha512"),
             ("sha224", "sha224"), ("sha384", "sha384"),
             ("ntlm", "NTLM（Windows）"), ("mysql", "MySQL PASSWORD()"),
         ]},
    ],
    "hashcrypto/crack": [
        {"key": "algo", "type": "text", "label": "算法", "placeholder": "不填自动识别"},
        {"key": "rules", "type": "check", "label": "启用变形规则（大小写/加数字后缀）"},
    ],
    "hashcrypto/xor": [
        {"key": "key", "type": "text", "label": "密钥 hex", "placeholder": "如 2A",
         "hint": "留空则单字节全试并排序"},
    ],
    "hashcrypto/aes": [
        {"key": "key", "type": "text", "label": "key (hex)",
         "placeholder": "16 字节 = 32 位 hex", "hint": "AES-128 是 32 位 hex"},
        {"key": "iv", "type": "text", "label": "iv (hex)",
         "placeholder": "16 字节 = 32 位 hex", "hint": "ECB 模式不需要 IV"},
        {"key": "mode", "type": "choice", "label": "模式", "default": "cbc",
         "choices": [("cbc", "CBC"), ("ecb", "ECB"), ("ctr", "CTR"), ("gcm", "GCM")]},
        {"key": "enc", "type": "check", "label": "加密方向"},
    ],
    "hashcrypto/rc4": [
        {"key": "key", "type": "text", "label": "密钥", "hint": "普通文本，不是 hex"},
    ],
    "hashcrypto/rsa": [
        {"key": "n", "type": "text", "label": "n", "placeholder": "十进制大整数",
         "hint": "模数；小到能分解才破得开"},
        {"key": "e", "type": "text", "label": "e", "placeholder": "通常 65537 或 3"},
        {"key": "c", "type": "text", "label": "密文 c", "hint": "十进制；不填就只做分解攻击"},
    ],
    "hashcrypto/jwt": [
        {"key": "crack", "type": "check", "label": "尝试爆破 HS256 密钥"},
    ],
    # 默认只露一个「格式预设」，选「自定义」才展开那些掩码参数 ——
    # 第一次用的人看到「掩码 ?d?d…」是不知所措的，先让他选「8 位数字」就能跑。
    "hashcrypto/mask": [
        {"key": "preset", "type": "choice", "label": "原文格式", "default": "d8",
         "choices": [
             ("d4", "4 位数字（0000-9999）"),
             ("d6", "6 位数字"),
             ("d8", "8 位数字（生日 / 日期最常见）"),
             ("d10", "10 位数字"),
             ("lower6", "6 位小写字母"),
             ("custom", "自定义掩码…"),
         ]},
        {"key": "mask", "type": "text", "label": "掩码",
         "placeholder": "如 ?d?d?d?d?d?d?d?d", "show_if": {"preset": "custom"},
         "hint": "?d 数字 ?l 小写 ?u 大写 ?a 全字符 ?h hex；留空则用长度+字符集"},
        {"key": "len", "type": "int", "label": "长度", "min": 1, "max": 12,
         "show_if": {"preset": "custom"}, "hint": "配合右边的字符集，如 8 + 数字"},
        {"key": "charset", "type": "choice", "label": "字符集", "default": "digits",
         "show_if": {"preset": "custom"},
         "choices": [("digits", "数字 0-9"), ("lower", "小写 a-z"),
                     ("upper", "大写 A-Z"), ("alnum", "大小写+数字"),
                     ("hex", "hex 0-9a-f")]},
        {"key": "prefix", "type": "text", "label": "前缀", "placeholder": "如 19"},
        {"key": "suffix", "type": "text", "label": "后缀", "placeholder": "可选"},
        {"key": "threads", "type": "int", "label": "进程数", "min": 1, "max": 64,
         "hint": "留空用满所有核心"},
    ],
    # ---------------- stego ----------------
    # 全自动就能出结果；这几个是「自动没对上」时的手动钉住手段。
    "stego/grid": [
        {"key": "cols", "type": "int", "label": "列数", "min": 1, "max": 9999,
         "hint": "自动把图边留白也数成一格时，用它钉住；留空即自动"},
        {"key": "rows", "type": "int", "label": "行数", "min": 1, "max": 9999,
         "hint": "同上"},
        {"key": "channel", "type": "choice", "label": "取色通道", "default": "",
         "choices": [("", "自动（对比度最大的）"), ("g", "绿"), ("r", "红"),
                     ("b", "蓝")]},
        {"key": "threshold", "type": "int", "label": "二值化阈值", "min": 0, "max": 255,
         "hint": "留空用 Otsu 自动算"},
        {"key": "order", "type": "choice", "label": "读取顺序", "default": "row",
         "choices": [("row", "按行"), ("col", "按列")]},
        {"key": "invert", "type": "check", "label": "强制深色=1",
         "hint": "默认两个方向都试；勾上就只认深色"},
    ],
    # ---------------- num ----------------
    # 只有一个选项：输入的那串数按什么进制读。输出固定是 2..36 全列。
    # 编码页的虚拟项（不在 DECODERS 里）
    "convert": _PARAMS_CONVERT,
    "num/convert": [
        {"key": "from", "type": "choice", "label": "按几进制读", "default": "",
         "choices": _NUM_BASES,
         "hint": "「自动识别」只认 0x/0b/0o 前缀和 a-f，其余一律当十进制；"
                 "原文是 12 进制这类就到这里选"},
    ],
}


# ---------------------------------------------------------------------------
# 给 classic 里可逆的手法统一补一个「加密方向」开关。
#
# 脚本层面这些手法早就支持 `--enc` 了，但界面没暴露，于是在界面里永远只能走
# 解码方向（bacon 更糟：main 里根本没接 enc，点编码会退化成解码返回一个字母）。
# 逐个手写容易漏，这里按名单批量补；已有 enc 参数的（playfair）跳过。
# 故意不含 sub / vigcrack / auto —— 它们是破解器，没有反方向。
# ---------------------------------------------------------------------------
_CLASSIC_REVERSIBLE = (
    "caesar", "vigenere", "affine", "bacon", "railfence", "columnar",
    "atbash", "a1z26", "polybius", "playfair", "adfgx", "keyboard", "t9",
)

for _name in _CLASSIC_REVERSIBLE:
    _lst = PARAMS.setdefault("classic/" + _name, [])
    if not any(p.get("key") == "enc" for p in _lst):
        _lst.append({
            "key": "enc", "type": "check", "label": "加密方向",
            "hint": "不勾 = 解码/爆破",
        })
