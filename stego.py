#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件隐写取证。

子命令：
  binwalk <file>              扫描内嵌文件特征（zip/png/jpg/gzip/pdf/rar/7z/sqlite/ELF）
  tail <file>                 检测文件尾附加数据（IEND / EOI / GIF 结束符之后的字节）
  strings <file> [-n 6]       可打印字符串，并标出可疑项（flag/URL/base64/长 hex）
  lsb <image>                 逐通道 LSB 提取，输出所有候选（含正序/倒序、RGB/RGBA）
  lsbscan <image>             同上但更彻底：1~3 位、6 种通道组合
  exif <image>                读元数据（EXIF / PNG 文本块 / 注释）
  pngchunks <png>             列出 PNG 每个块，标出可疑块
  zipinfo <zip>               不依赖 unzip：列条目、注释、伪加密标记
  unzip <zip> [--out DIR]     解压到目录（store/deflate，加密条目跳过，带路径越界防护）
  hexdump <file> [-l N]       十六进制查看
  qr <image>                  用 zbarimg 识别二维码/条形码（--all 放大 2x/4x 重试）
  spec <audio> [--out a.png]  ffmpeg 生成频谱图（看隐藏的摩斯/文字）
  grid <image>                点阵图切成格子读 bit 流，自动拼字节并猜文本编码
                              （自动测格宽/相位/阈值；--cell/--off/--cols/--rows 可覆盖）
  meta <file>                 文件类型 + 尺寸 + 熵

通用：
  -q, --quiet                 只输出结果

例：
  stego.py binwalk mystery.png
  stego.py tail photo.jpg
  stego.py lsbscan cover.png
"""
import sys
import os
import re
import zlib
import struct
import subprocess
import math
import json
import shutil
import tempfile

try:
    from PIL import Image
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False

# ---------------------------------------------------------------- 魔数

MAGIC = [
    (b"PK\x03\x04", "zip/压缩包", 0),
    (b"PK\x05\x06", "zip 空档案", 0),
    (b"\x89PNG\r\n\x1a\n", "PNG", 0),
    (b"\xff\xd8\xff", "JPEG", 0),
    (b"GIF87a", "GIF", 0),
    (b"GIF89a", "GIF", 0),
    (b"BM", "BMP", 0),
    (b"RIFF", "RIFF (WAV/AVI/WebP)", 0),
    (b"OggS", "OGG", 0),
    (b"ID3", "MP3(ID3)", 0),
    (b"\xff\xfb", "MP3", 0),
    (b"fLaC", "FLAC", 0),
    (b"%PDF", "PDF", 0),
    (b"\x1f\x8b\x08", "gzip", 0),
    (b"BZh", "bzip2", 0),
    (b"\xfd7zXZ\x00", "xz", 0),
    (b"7z\xbc\xaf\x27\x1c", "7z", 0),
    (b"Rar!\x1a\x07", "RAR", 0),
    (b"SQLite format 3", "SQLite", 0),
    (b"\x7fELF", "ELF 可执行", 0),
    (b"\xd0\xcf\x11\xe0", "MS Office 旧格式", 0),
    (b"MZ", "PE/EXE", 0),
    (b"-----BEGIN", "PEM 密钥/证书", 0),
]


def read(path):
    with open(path, "rb") as f:
        return f.read()


def _magic_plausible(data, i, name):
    """2 字节魔数在任意二进制里平均每 64KB 就撞一次，光看魔数必然刷出一堆假阳性。

    BMP 的 "BM" 后面 4 字节是文件大小；PE 的 MZ 头 0x3C 处是 e_lfanew，
    应当指向 "PE\\0\\0"。用这两条把误报压下去。
    """
    if name == "BMP":
        if i + 6 > len(data):
            return False
        size = struct.unpack("<I", data[i + 2:i + 6])[0]
        return 14 <= size <= len(data) + 4096
    if name == "PE/EXE":
        if i + 0x40 > len(data):
            return False
        lfanew = struct.unpack("<I", data[i + 0x3C:i + 0x40])[0]
        if not (0 < lfanew < 4096):
            return False
        j = i + lfanew
        return j + 4 <= len(data) and data[j:j + 4] == b"PE\x00\x00"
    return True


def binwalk(data):
    hits = []
    for magic, name, _off in MAGIC:
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            if _magic_plausible(data, i, name):
                hits.append((i, name))
            start = i + 1
            if start > len(data):
                break
    hits.sort()
    # 同位置只留一个
    out, seen = [], set()
    for off, name in hits:
        if off in seen:
            continue
        seen.add(off)
        out.append((off, name))
    return out


def _gif_end(data):
    """解析 GIF 块结构，返回 trailer(0x3B) 之后的位置；解析失败返回 None。

    不能用 data.rfind(b"\\x3b")：0x3B 就是 ASCII 的 ';'，LZW 压缩数据里
    出现它的概率不低，rfind 很可能把某个 ';' 当成"文件末尾"，于是偏移全错。
    """
    if len(data) < 13 or data[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    flags = data[10]
    pos = 13
    if flags & 0x80:                      # 全局色表
        pos += 3 * (2 ** ((flags & 0x07) + 1))
    while pos < len(data):
        b = data[pos]
        if b == 0x3B:                     # 真正的 trailer
            return pos + 1
        if b == 0x21:                     # 扩展块：0x21 + label
            pos += 2
        elif b == 0x2C:                   # 图像描述符
            if pos + 10 > len(data):
                return None
            lflags = data[pos + 9]
            pos += 10
            if lflags & 0x80:             # 局部色表
                pos += 3 * (2 ** ((lflags & 0x07) + 1))
            pos += 1                      # LZW 最小码长
        else:
            return None
        while pos < len(data):            # 跳过子块串（长度 0 结束）
            n = data[pos]
            pos += 1 + n
            if n == 0:
                break
        else:
            return None
    return None


def tail_data(data):
    """找"文件正式结束符之后还有东西"的情况"""
    res = []
    # PNG
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        i = data.rfind(b"IEND")
        if i >= 0:
            end = i + 8
            if end < len(data):
                res.append(("PNG IEND", end, data[end:]))
    # JPEG
    if data[:3] == b"\xff\xd8\xff":
        i = data.rfind(b"\xff\xd9")
        if i >= 0 and i + 2 < len(data):
            res.append(("JPEG EOI", i + 2, data[i + 2:]))
    # GIF
    end = _gif_end(data)
    if end is not None and end < len(data):
        res.append(("GIF trailer", end, data[end:]))
    # ZIP（找最后一个 EOCD 之后）
    i = data.rfind(b"PK\x05\x06")
    if i >= 0 and i + 22 <= len(data):
        comment_len = struct.unpack("<H", data[i + 20:i + 22])[0]
        end = i + 22 + comment_len
        if end < len(data):
            res.append(("ZIP EOCD", end, data[end:]))
    return res


def strings(data, minlen=6):
    # 正则下界必须跟着 minlen 走：原来写死 {4,}，于是 -n 2 时 2~3 字符的串
    # 在正则阶段就被切掉了，参数看起来生效其实完全没用。
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, int(minlen)))
    return [(m.start(), m.group().decode("latin-1")) for m in pat.finditer(data)]


SUSPECT = [
    ("flag", re.compile(r"flag\{|ctf\{|key\{|FLAG")),
    ("URL", re.compile(r"https?://")),
    ("base64长串", re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")),
    ("长hex", re.compile(r"\b[0-9a-fA-F]{24,}\b")),
    ("路径", re.compile(r"[A-Za-z]:\\|/home/|/tmp/|\.\./")),
    ("密码字样", re.compile(r"(?i)pass(word|wd)?|secret|token|key\s*=")),
]


def mark_suspect(s):
    tags = []
    for name, pat in SUSPECT:
        if pat.search(s):
            tags.append(name)
    return tags


# ---------------------------------------------------------------- 图片

def open_img(path):
    if not HAVE_PIL:
        raise RuntimeError("需要 Pillow")
    im = Image.open(path)
    im.load()
    return im


CHANNELS = {
    "r": 0, "g": 1, "b": 2, "a": 3,
}


def bytes_to_bits(b, msb=True):
    bits = []
    for byte in b:
        rng = range(7, -1, -1) if msb else range(8)
        for i in rng:
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for j in range(8):
            v = (v << 1) | bits[i + j]
        out.append(v)
    return bytes(out)


def lsb_extract(im, channels="rgb", bit=0, msb=True, limit=200000):
    """按像素顺序取指定通道的第 bit 位（bit=0 是最低位）"""
    if im.mode not in ("RGB", "RGBA"):
        im = im.convert("RGBA")
    raw = im.tobytes()
    nch = len(im.getbands())
    idxs = [CHANNELS[c] for c in channels if c in CHANNELS and CHANNELS[c] < nch]
    if not idxs:
        idxs = [0, 1, 2]
    bits = []
    for p in range(0, len(raw), nch):
        for ci in idxs:
            v = raw[p + ci]
            bits.append((v >> bit) & 1)
            if len(bits) >= limit:
                break
        if len(bits) >= limit:
            break
    return bits_to_bytes(bits)


def printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / len(b)


def longest_printable(b, minlen=8):
    """找出最长的一段连续可打印字节。

    不能用"整体可打印率"筛选：图像里藏 20 字节的 flag 时，
    后面几万个字节全是噪声，整体可打印率算出来不到 10%，真答案会被直接过滤掉。
    """
    best = b""
    cur = bytearray()
    for c in b:
        if 32 <= c < 127 or c in (9, 10, 13):
            cur.append(c)
        else:
            if len(cur) > len(best):
                best = bytes(cur)
            cur = bytearray()
    if len(cur) > len(best):
        best = bytes(cur)
    return best if len(best) >= minlen else b""


def lsb_scan(path, max_bit=3):
    im = open_img(path)
    results = []
    for channels in ("rgb", "rgba", "r", "g", "b"):
        for bit in range(max_bit):
            try:
                out = lsb_extract(im, channels, bit)
            except Exception:
                continue
            frag = longest_printable(out)
            if frag:
                results.append((len(frag), channels, bit, out, frag))
    results.sort(key=lambda x: -x[0])
    return results


def png_chunks(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("不是 PNG")
    pos = 8
    out = []
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8].decode("latin-1")
        body = data[pos + 8:pos + 8 + length]
        out.append((ctype, length, body))
        pos += 12 + length
        if ctype == "IEND":
            break
    return out


def png_text(chunks):
    texts = []
    for ctype, length, body in chunks:
        try:
            if ctype == "tEXt":
                k, _, v = body.partition(b"\x00")
                texts.append((k.decode("latin-1"), v.decode("latin-1", "replace")))
            elif ctype == "iTXt":
                parts = body.split(b"\x00", 5)
                if len(parts) >= 6:
                    texts.append((parts[0].decode("latin-1"), parts[-1].decode("utf-8", "replace")))
            elif ctype == "zTXt":
                k, _, rest = body.partition(b"\x00")
                try:
                    texts.append((k.decode("latin-1"), zlib.decompress(rest[1:]).decode("utf-8", "replace")))
                except Exception:
                    pass
        except Exception:
            continue
    return texts


def exif_info(path):
    info = {}
    im = open_img(path)
    info["format"] = im.format
    info["mode"] = im.mode
    info["size"] = im.size
    if im.info:
        for k, v in im.info.items():
            if isinstance(v, bytes):
                try:
                    v = v.decode("utf-8", "replace")
                except Exception:
                    v = repr(v[:80])
            s = str(v)
            info[k] = s[:500]
    try:
        ex = im.getexif()
        for tag, val in ex.items():
            info["exif:%s" % tag] = str(val)[:500]
    except Exception:
        pass
    if im.format == "PNG":
        try:
            ch = png_chunks(read(path))
            for k, v in png_text(ch):
                info["png:%s" % k] = v[:500]
        except Exception:
            pass
    return info


# ---------------------------------------------------------------- ZIP

def zip_entries(data):
    """不依赖 unzip，自己解析中央目录"""
    entries = []
    i = 0
    while True:
        i = data.find(b"PK\x01\x02", i)
        if i < 0:
            break
        if i + 46 > len(data):
            break
        try:
            (ver, ver_needed, flags, method, mtime, mdate, crc, csize, usize,
             fnlen, extralen, commentlen, disk, iattr, eattr, offset) = struct.unpack(
                "<HHHHHHIIIHHHHHII", data[i + 4:i + 46])
        except Exception:
            break
        name = data[i + 46:i + 46 + fnlen].decode("utf-8", "replace")
        entries.append({
            "name": name,
            "flags": flags,
            "encrypted": bool(flags & 0x1),
            "strong_enc": bool(flags & 0x40),
            "method": method,
            "csize": csize,
            "usize": usize,
            "offset": offset,
        })
        i += 4
    return entries


def zip_comment(data):
    i = data.rfind(b"PK\x05\x06")
    if i < 0 or i + 22 > len(data):
        return None
    clen = struct.unpack("<H", data[i + 20:i + 22])[0]
    if clen == 0:
        return None
    return data[i + 22:i + 22 + clen]


def zip_fake_encrypt(entries, data):
    """伪加密：flag 说加密了，但实际数据没加密（可以用 0 长度 CRC 判断）"""
    out = []
    for e in entries:
        if not e["encrypted"]:
            continue
        off = e["offset"]
        if off + 30 > len(data) or data[off:off + 4] != b"PK\x03\x04":
            continue
        flags = struct.unpack("<H", data[off + 6:off + 8])[0]
        name_len = struct.unpack("<H", data[off + 26:off + 28])[0]
        extra_len = struct.unpack("<H", data[off + 28:off + 30])[0]
        payload = data[off + 30 + name_len + extra_len: off + 30 + name_len + extra_len + min(e["csize"], 32)]
        # 伪加密的典型特征：局部头的 flag 与中央目录不一致，或数据能直接看出明文
        out.append({"name": e["name"], "local_flags": flags,
                    "central_flags": e["flags"],
                    "inconsistent": flags != e["flags"]})
    return out


def zip_extract(data, entries):
    """用标准库解压。只支持 store/deflate；加密条目返回 None。

    原来有个 password 参数但完全没用到——标准库 zipfile 不支持解密，
    留着只会让人以为能解密码。
    """
    import io
    import zipfile
    buf = io.BytesIO(data)
    zf = zipfile.ZipFile(buf)
    res = {}
    for e in entries:
        try:
            res[e["name"]] = zf.read(e["name"])
        except Exception:
            # 加密、损坏、不支持的压缩算法都会走到这里
            res[e["name"]] = None
    return res


# ---------------------------------------------------------------- 音频

def spectrum(path, out=None):
    # 不要写死 /tmp：Windows 上根本没有这个目录，会直接失败
    out = out or os.path.join(tempfile.gettempdir(), "spectrum.png")
    if not os.path.exists(path):
        raise RuntimeError("文件不存在：%s" % path)
    # 必须先 shutil.which 找 ffmpeg。直接 subprocess.run(["ffmpeg", ...]) 时，
    # 如果 ffmpeg 不在 PATH，Windows 抛的是 `[WinError 2] 系统找不到指定的文件`
    # —— 看起来像「输入文件不存在」，实际上是找不到 ffmpeg 这个可执行文件，
    # 极容易误导。qr_scan 那边早就是这么写的，这里漏了。
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise RuntimeError(
            "需要 ffmpeg，但 PATH 里找不到。\n"
            "  Windows：下载 ffmpeg 后把 ffmpeg.exe 所在目录加进系统 PATH，重开终端\n"
            "  macOS  ：brew install ffmpeg\n"
            "  Debian ：sudo apt install ffmpeg")
    cmd = [ffmpeg, "-y", "-v", "error", "-i", path,
           "-lavfi", "showspectrumpic=s=1600x900:legend=1:scale=log", out]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode("utf-8", "replace")[:400])
    return out


def qr_scan(path, allres=False):
    # 不能写死 /usr/bin/zbarimg：macOS 的 Homebrew 装在 /opt/homebrew/bin，
    # Windows 上是 zbarimg.exe，写死路径会误判成"没装"。
    zbar = shutil.which("zbarimg")
    if not zbar:
        raise RuntimeError("需要 zbarimg（apt install zbar-tools / brew install zbar）")
    outs = []
    r = subprocess.run([zbar, "--raw", "-q", path], capture_output=True)
    if r.stdout.strip():
        outs.extend(r.stdout.decode("utf-8", "replace").splitlines())
    if allres and HAVE_PIL:
        # 放大后再试一次，小二维码原图识别不出
        im = open_img(path).convert("L")
        w, h = im.size
        for scale in (2, 4):
            fd, tmp = tempfile.mkstemp(suffix=".png", prefix="_qr_%dx_" % scale)
            os.close(fd)
            try:
                im.resize((w * scale, h * scale), Image.LANCZOS).save(tmp)
                r = subprocess.run([zbar, "--raw", "-q", tmp], capture_output=True)
                if r.stdout.strip():
                    outs.extend(r.stdout.decode("utf-8", "replace").splitlines())
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    seen, uniq = set(), []
    for o in outs:
        if o not in seen:
            seen.add(o)
            uniq.append(o)
    return uniq


# ---------------------------------------------------------------- 点阵网格（grid）
#
# 把「一格一色」的点阵图切成格子，读出 bit 流，再拼成字节。
# 典型场景：ARG 里那种放大了是像素方块、每块代表 0/1 的图。
# 纯标准库：PNG 自己解（非隔行），其它格式才退回 Pillow。

_PNG_NCH = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def _png_canvas(data):
    """纯标准库解非隔行 PNG。返回 (w, h, [R, G, B, A])，平面都是 bytes(w*h)。"""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("不是 PNG")
    pos, n = 8, len(data)
    w = h = depth = ctype = interlace = None
    idat, plte = [], b""
    while pos + 8 <= n:
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + ln]
        pos += 12 + ln
        if typ == b"IHDR":
            w, h, depth, ctype, _c, _f, interlace = struct.unpack(">IIBBBBB", body)
        elif typ == b"PLTE":
            plte = body
        elif typ == b"IDAT":
            idat.append(body)
        elif typ == b"IEND":
            break
    if w is None:
        raise ValueError("PNG 缺 IHDR")
    if interlace:
        raise ValueError("隔行(interlace)PNG 解不了，先转成非隔行")
    nch = _PNG_NCH.get(ctype)
    if nch is None:
        raise ValueError("不支持的 PNG 颜色类型 %d" % ctype)
    raw = zlib.decompress(b"".join(idat))
    bits_pp = nch * depth
    stride = (w * bits_pp + 7) // 8
    bpp = max(1, (bits_pp + 7) // 8)
    prev = bytes(stride)
    rows = []
    p = 0
    for _y in range(h):
        if p + 1 + stride > len(raw):
            raise ValueError("PNG 像素数据被截断")
        ft = raw[p]
        cur = bytearray(raw[p + 1:p + 1 + stride])
        p += 1 + stride
        if ft == 1:
            for i in range(bpp, stride):
                cur[i] = (cur[i] + cur[i - bpp]) & 0xFF
        elif ft == 2:
            for i in range(stride):
                cur[i] = (cur[i] + prev[i]) & 0xFF
        elif ft == 3:
            for i in range(stride):
                a = cur[i - bpp] if i >= bpp else 0
                cur[i] = (cur[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ft == 4:
            for i in range(stride):
                a = cur[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                pa = abs(b - c)
                pb = abs(a - c)
                pc = abs(a + b - 2 * c)
                if pa <= pb and pa <= pc:
                    pr = a
                elif pb <= pc:
                    pr = b
                else:
                    pr = c
                cur[i] = (cur[i] + pr) & 0xFF
        elif ft != 0:
            raise ValueError("未知 PNG 滤波类型 %d" % ft)
        rows.append(cur)
        prev = cur

    R = bytearray(w * h)
    G = bytearray(w * h)
    B = bytearray(w * h)
    A = bytearray(b"\xff" * (w * h))
    for y in range(h):
        row = rows[y]
        idx = y * w
        if depth == 8:
            vals = row
        elif depth == 16:
            vals = row[0:2 * w * nch:2]
        else:
            per = 8 // depth
            maxv = (1 << depth) - 1
            vals = bytearray(w * nch)
            for i in range(w * nch):
                vals[i] = (row[i // per] >> (8 - depth * (i % per + 1))) & maxv
            if ctype in (0, 4):
                vals = bytearray(v * 255 // maxv for v in vals)
        if ctype == 2:
            R[idx:idx + w] = vals[0:3 * w:3]
            G[idx:idx + w] = vals[1:3 * w:3]
            B[idx:idx + w] = vals[2:3 * w:3]
        elif ctype == 6:
            R[idx:idx + w] = vals[0:4 * w:4]
            G[idx:idx + w] = vals[1:4 * w:4]
            B[idx:idx + w] = vals[2:4 * w:4]
            A[idx:idx + w] = vals[3:4 * w:4]
        elif ctype == 0:
            R[idx:idx + w] = vals[0:w]
            G[idx:idx + w] = vals[0:w]
            B[idx:idx + w] = vals[0:w]
        elif ctype == 4:
            R[idx:idx + w] = vals[0:2 * w:2]
            G[idx:idx + w] = vals[0:2 * w:2]
            B[idx:idx + w] = vals[0:2 * w:2]
            A[idx:idx + w] = vals[1:2 * w:2]
        elif ctype == 3:
            for x in range(w):
                k = vals[x] * 3
                if k + 2 < len(plte):
                    R[idx + x] = plte[k]
                    G[idx + x] = plte[k + 1]
                    B[idx + x] = plte[k + 2]
    return w, h, [bytes(R), bytes(G), bytes(B), bytes(A)]


def canvas_of(path):
    """返回 (w, h, [R, G, B, A])。PNG 走内置解码，其它格式退回 Pillow。"""
    data = read(path)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        try:
            return _png_canvas(data)
        except Exception:
            if not HAVE_PIL:
                raise
    if not HAVE_PIL:
        raise RuntimeError("这张图不是 PNG，且没装 Pillow")
    im = Image.open(path)
    im.load()
    im = im.convert("RGBA")
    w, h = im.size
    raw = im.tobytes()
    return w, h, [raw[0::4], raw[1::4], raw[2::4], raw[3::4]]


def _otsu_split(vals):
    """一维 Otsu。返回 (阈值, 类间方差)。方差大 = 两色分得开。

    两峰之间常常是空地，最佳阈值是一整段平台；取平台左端会把紧贴低峰的格子
    判反（实测：低峰拖到 56、阈值落在 55，那格就翻面了）。所以取平台中点。
    """
    hist = [0] * 256
    for v in vals:
        hist[0 if v < 0 else (255 if v > 255 else int(v))] += 1
    total = len(vals)
    if not total:
        return 128.0, 0.0
    sum_all = sum(i * c for i, c in enumerate(hist))
    w_b = 0
    sum_b = 0
    scores = [0.0] * 256
    for t in range(256):
        w_b += hist[t]
        sum_b += t * hist[t]
        w_f = total - w_b
        if w_b == 0 or w_f == 0:
            scores[t] = -1.0
            continue
        m_b = sum_b / w_b
        m_f = (sum_all - sum_b) / w_f
        scores[t] = w_b * w_f * (m_b - m_f) ** 2
    mx = max(scores)
    if mx <= 0:
        return 128.0, 0.0
    plat = [t for t, s in enumerate(scores) if s >= mx * (1 - 1e-6)]
    return float(sum(plat)) / len(plat), mx


def _fit_axis(prof, min_cell=3):
    """从「相邻像素差」曲线找格宽与相位。返回 (period, phase, score)。

    打分 = (边界强度/全图平均强度) x (强峰覆盖率)。两处都是血的教训：
    - 分母若用「内部平均」，遇到边缘锐利的图（内部差恒为 0）会除零爆炸，
      挑出格宽 4.1 这种假周期；用全图均值就稳定。
    - 只看强度比值会选到「格宽 117」：边界数一少，几个最陡的点就能把均值刷高。
      强峰只可能来自格线（相邻同色时格线没有峰，所以反过来不成立），
      拿覆盖率去卡，错误周期就露馅了。
    （再乘一个「边界捕获的能量占比」试过，反而让格宽 3 这种过密周期赢，
      因为边界越密捕获得越多——所以没有采用。）
    """
    n = len(prof)
    if n < 12:
        raise ValueError("图太小")
    total = float(sum(prof))
    if total <= 0:
        raise ValueError("这张图几乎没对比度")
    max_lag = max(min_cell + 3, n // 3)

    # 纯色块图里绝大多数相邻差是 0，75 分位数会退化成 0，这时用最大值兜底
    srt = sorted(prof)
    q = srt[int(len(srt) * 0.75)]
    if q <= 0:
        q = 0.1 * srt[-1]
    # 峰位置用连续坐标：prof[i] 描述的是 i 与 i+1 之间的那条边界，即 i+0.5
    peaks = [i + 0.5 for i in range(1, n - 1)
             if prof[i] >= q and prof[i] >= prof[i - 1] and prof[i] >= prof[i + 1]]
    if not peaks:
        peaks = [i + 0.5 for i in range(1, n - 1) if prof[i] >= q]
    if not peaks:
        raise ValueError("找不到格线峰")
    gmean = total / n

    def at(v):
        """在连续坐标 v 处线性插值取边界强度（整数取样会把相位锁死到 1px）。"""
        t = v - 0.5
        if t <= 0.0:
            return float(prof[0])
        if t >= n - 1:
            return float(prof[n - 1])
        i = int(t)
        f = t - i
        return prof[i] * (1.0 - f) + prof[i + 1] * f

    def evaluate(phase, period):
        edge = []
        k = 0
        while True:
            v = phase + k * period
            if v >= n:
                break
            if v >= 0:
                edge.append(v)
            k += 1
        m = len(edge)
        if m < 5 or m > n - 3:
            return -1.0
        s = 0.0
        for v in edge:
            s += at(v)
        j = 0
        hit = 0
        for pk in peaks:
            while j < m and edge[j] < pk - 1.5:
                j += 1
            if j < m and abs(edge[j] - pk) <= 1.5:
                hit += 1
        cov = hit / float(len(peaks))
        if cov <= 0:
            return -1.0
        return ((s / m) / gmean) * cov

    # 粗搜必须带小数：图像缩放过以后格宽是 10.66 这种，整数周期会一路漂移、
    # 得分被「格宽 32」这种侥幸对齐三个峰的错误周期反超，细化就再也回不去了。
    cand = []
    pstep = 0.25 if n <= 1500 else 0.5
    p = float(min_cell)
    while p <= max_lag:
        ph = 0.0
        phstep = 0.5 if p <= 20 else 1.0
        while ph < p:
            sc = evaluate(ph, p)
            if sc > 0:
                cand.append((sc, p, ph))
            ph += phstep
        p += pstep
    if not cand:
        raise ValueError("没找到周期性网格")
    cand.sort(reverse=True)

    # 留几个互相隔开的候选各自细化，别把鸡蛋放在一个篮子里
    seeds = []
    for sc, p, ph in cand:
        if all(abs(p - q) >= 1.0 for _s, q, _pq in seeds):
            seeds.append((sc, p, ph))
        if len(seeds) >= 6:
            break

    best = (-1.0, None, 0.0)
    for sc, p, ph in seeds:
        st = 0.2
        for _ in range(10):
            improved = False
            for dp in (-2 * st, -st, 0.0, st, 2 * st):
                np_ = p + dp
                if np_ < min_cell:
                    continue
                for dph in (-2 * st, -st, 0.0, st, 2 * st):
                    rr = evaluate(ph + dph, np_)
                    if rr > sc:
                        sc, p, ph = rr, np_, ph + dph
                        improved = True
            if not improved:
                st /= 2.0
        if sc > best[0]:
            best = (sc, p, ph)
    sc, p, ph = best
    # 相位只规范到 [0, p)。要不要再减一个周期，得看图像边缘是留白还是格子内容，
    # 那是二维信息、一维的 prof 判断不了，交给 grid_read 用颜色方差定。
    return p, ph % p, sc


def _parse_pair(s, default=None):
    """解析 "12.9" / "12.9x12.5" / "6.25,12.5"。"""
    if s is None:
        return default
    for sep in ("x", "X", ",", " "):
        if sep in s:
            a, b = s.split(sep, 1)
            return (float(a), float(b))
    v = float(s)
    return (v, v)


def grid_read(path, channel=None, cols=None, rows=None, cell=None, off=None,
              threshold=None, invert=None, order="row"):
    """切格子 -> bit 流 -> 字节 -> 猜文本编码。返回 dict。"""
    w, h, planes = canvas_of(path)
    if w * h > 6000000:
        raise ValueError("图太大（%dx%d），先裁小一点" % (w, h))

    names = ["r", "g", "b"]
    if channel:
        ci = names.index(channel.lower())
        tglob, vglob = _otsu_split(planes[ci])
    else:
        ci, vglob, tglob = 0, -1.0, 128
        for i in range(3):
            t, v = _otsu_split(planes[i])
            if v > vglob:
                ci, vglob, tglob = i, v, t
    P = planes[ci]
    chan = names[ci]

    pw, ph_ = _parse_pair(cell, (None, None))
    ox, oy = _parse_pair(off, (None, None))

    note = []
    if pw is None or ox is None:
        colprof = [0.0] * (w - 1)
        for y in range(h):
            base = y * w
            for x in range(w - 1):
                d = P[base + x + 1] - P[base + x]
                colprof[x] += d if d > 0 else -d
        pw, ox, rx = _fit_axis(colprof)
        note.append("横向从 x=%.2f 起，格宽 %.2f（得分 %.2f）" % (ox, pw, rx))
    if ph_ is None or oy is None:
        rowprof = [0.0] * (h - 1)
        for y in range(h - 1):
            base, base2 = y * w, (y + 1) * w
            for x in range(w):
                d = P[base2 + x] - P[base + x]
                rowprof[y] += d if d > 0 else -d
        ph_, oy, ry = _fit_axis(rowprof)
        note.append("纵向从 y=%.2f 起，格高 %.2f（得分 %.2f）" % (oy, ph_, ry))

    # 相位接近整周期时，「起点 p-ε」和「起点 -ε」是同一个网格，但格数差一整格。
    # 光看相位分不出来：顶部留白 13px 的图，起点该是 12.5（留白不算格子）；
    # 而紧贴图边缘的完整网格，起点该是 -0.5（否则少一列）。
    # 区别只在于图边缘那一条到底是「均匀留白」还是「格子内容」，所以比颜色方差。
    def _var(x0, x1, y0, y1):
        s = 0
        s2 = 0
        c = 0
        for yy in range(y0, y1):
            base = yy * w
            for xx in range(x0, x1):
                v = P[base + xx]
                s += v
                s2 += v * v
                c += 1
        if not c:
            return 0.0
        m = s / float(c)
        return s2 / float(c) - m * m

    v_all = _var(0, w, 0, h)
    if v_all > 0:
        if ox > pw * 0.6 and _var(0, max(1, int(ox)), 0, h) > 0.4 * v_all:
            ox -= pw
        if oy > ph_ * 0.6 and _var(0, w, 0, max(1, int(oy))) > 0.4 * v_all:
            oy -= ph_

    # 末尾那格常常只剩大半个：留 15% 容差，别把整列/整行丢掉
    ncol = cols if cols else int((w - ox + pw * 0.15) // pw)
    nrow = rows if rows else int((h - oy + ph_ * 0.15) // ph_)
    if ncol < 1 or nrow < 1:
        raise ValueError("算出 %dx%d 格，检查 --cell / --off" % (ncol, nrow))

    vals = []
    for r in range(nrow):
        ay = oy + r * ph_
        for c in range(ncol):
            ax = ox + c * pw
            x0 = int(round(ax + pw * 0.25))
            x1 = int(round(ax + pw * 0.75))
            y0 = int(round(ay + ph_ * 0.25))
            y1 = int(round(ay + ph_ * 0.75))
            x0 = max(0, min(w - 1, x0))
            y0 = max(0, min(h - 1, y0))
            x1 = max(x0 + 1, min(w, x1))
            y1 = max(y0 + 1, min(h, y1))
            s = 0
            nn = 0
            for yy in range(y0, y1):
                base = yy * w
                for xx in range(x0, x1):
                    s += P[base + xx]
                    nn += 1
            vals.append(s / nn if nn else 0.0)

    if threshold is None:
        thr = _otsu_split(vals)[0]
    else:
        thr = float(threshold)
        ones = sum(1 for v in vals if v > thr)
        if ones == 0 or ones == len(vals):
            # 阈值把所有格子判成同一类 = 这个结果必然是废的（界面把「留空」
            # 发成 0 时就是这样），直接退回自动阈值并说明，别让用户对着
            # 一整片 ### 猜哪儿错了。
            auto = _otsu_split(vals)[0]
            note.append("给定阈值 %g 把 %d 个格子全判成一类，已改为自动阈值 %.0f"
                        % (threshold, len(vals), auto))
            thr = auto
    bright = [1 if v > thr else 0 for v in vals]

    def bits_of(rev):
        out = []
        if order == "col":
            seq = [bright[r * ncol + c] for c in range(ncol) for r in range(nrow)]
        else:
            seq = list(bright)
        for b in seq:
            out.append(1 - b if rev else b)
        return out

    def to_bytes(bits):
        bb = bytearray()
        for i in range(0, len(bits) - 7, 8):
            v = 0
            for j in range(8):
                v = (v << 1) | bits[i + j]
            bb.append(v)
        return bytes(bb)

    def guess(raw):
        raw = raw.rstrip(b"\x00")
        if len(raw) < 2:
            return None
        for enc in ("utf-8", "gb18030"):
            try:
                s = raw.decode(enc)
            except Exception:
                continue
            if all(ch.isprintable() or ch in "\n\r\t" for ch in s):
                return enc, s
        return None

    # 极性：点阵图里「浅色=1」很常见，肉眼完全看不出来，所以默认两个方向都试；
    # 但明确给了 --invert 就严格照它来，不偷偷翻回去。
    if invert is None:
        used = False
        raw = to_bytes(bits_of(False))
        dec = guess(raw)
        if dec is None:
            alt = to_bytes(bits_of(True))
            g = guess(alt)
            if g is not None:
                used, raw, dec = True, alt, g
    else:
        used = invert
        raw = to_bytes(bits_of(used))
        dec = guess(raw)

    bits = bits_of(used)
    return {
        "w": w, "h": h, "channel": chan, "note": note,
        "cell": (pw, ph_), "off": (ox, oy),
        "cols": ncol, "rows": nrow, "threshold": thr,
        "vals": vals, "invert": used, "order": order,
        "bits": bits, "raw": raw, "decode": dec, "nbits": len(bits),
    }


def print_grid(res, quiet=False):
    if not quiet:
        print("图片 %dx%d，用 %s 通道" % (res["w"], res["h"], res["channel"].upper()))
        for line in res["note"]:
            print("  " + line)
        print("格子 %d 列 x %d 行，阈值 %.0f，%s" % (
            res["cols"], res["rows"], res["threshold"],
            "深色=1" if res["invert"] else "亮色=1"))
    nc = res["cols"]
    print()
    for r in range(res["rows"]):
        line = "".join("#" if b else "." for b in res["bits"][r * nc:(r + 1) * nc])
        print("  %2d %s" % (r, line))
    print()
    print("位流 %d 位 = %d 字节（按%s读取）" % (
        res["nbits"], res["nbits"] // 8, "列" if res["order"] == "col" else "行"))
    if res["nbits"] % 8:
        print("  注意：%d 位凑不满整字节，末尾 %d 位被丢掉" % (
            res["nbits"], res["nbits"] % 8))
    raw = res["raw"]
    if raw:
        print()
        for i in range(0, len(raw), 16):
            chunk = raw[i:i + 16]
            print("  %04x  %-47s  %s" % (
                i, " ".join("%02x" % b for b in chunk),
                "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)))
    if res["decode"]:
        enc, text = res["decode"]
        print()
        print("解出文本（%s）：" % enc)
        print("  " + text)
    elif raw:
        print()
        print("  （不像可读文本；再换 --order / 阈值 / 通道 试试）")


# ---------------------------------------------------------------- 杂项

def entropy(b):
    if not b:
        return 0.0
    freq = {}
    for c in b:
        freq[c] = freq.get(c, 0) + 1
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def meta(path):
    data = read(path)
    t = "未知"
    for magic, name, _ in MAGIC:
        if data.startswith(magic):
            t = name
            break
    info = {
        "file": path,
        "size": len(data),
        "type": t,
        "entropy": round(entropy(data[:200000]), 3),
    }
    if HAVE_PIL and t in ("PNG", "JPEG", "GIF", "BMP", "RIFF (WAV/AVI/WebP)"):
        try:
            im = open_img(path)
            info["image_size"] = list(im.size)
            info["mode"] = im.mode
        except Exception:
            pass
    return info


def hexdump(data, limit=512):
    out = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        hexs = " ".join("%02x" % c for c in chunk)
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("%08x  %-47s  %s" % (i, hexs, txt))
    return "\n".join(out)


# ---------------------------------------------------------------- CLI

def main():
    argv = sys.argv[1:]
    quiet = "-q" in argv or "--quiet" in argv
    argv = [a for a in argv if a not in ("-q", "--quiet")]
    use_all = "--all" in argv
    argv = [a for a in argv if a != "--all"]

    def opt(name, cast=str, default=None):
        nonlocal argv
        if name in argv:
            i = argv.index(name)
            v = cast(argv[i + 1])
            argv = argv[:i] + argv[i + 2:]
            return v
        return default

    minlen = opt("-n", int, 6)
    out = opt("--out", str, None)

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0

    cmd = argv[0]
    if len(argv) < 2 and cmd not in ("help",):
        print("缺少文件参数")
        return 2
    path = argv[1] if len(argv) > 1 else None

    try:
        if cmd == "binwalk":
            data = read(path)
            hits = binwalk(data)
            if quiet:
                for off, name in hits:
                    print("%d %s" % (off, name))
                return 0
            print("特征扫描（%d 字节）：" % len(data))
            for off, name in hits:
                print("  0x%08x  %s" % (off, name))
            return 0

        if cmd == "tail":
            data = read(path)
            res = tail_data(data)
            if not res:
                print("没有检测到文件尾附加数据")
                return 0
            for name, end, extra in res:
                print("%s 结束于 0x%x，之后还有 %d 字节：" % (name, end, len(extra)))
                print(hexdump(extra, 256))
                subs = binwalk(extra)
                if subs:
                    print("  附加数据里发现：")
                    for off, nm in subs:
                        print("    0x%x %s" % (off, nm))
            return 0

        if cmd == "strings":
            data = read(path)
            rows = strings(data, minlen)
            n_hit = 0
            for off, s in rows:
                tags = mark_suspect(s)
                if tags:
                    n_hit += 1
                if quiet:
                    if tags:
                        print(s)
                else:
                    mark = ("  <== " + ",".join(tags)) if tags else ""
                    print("0x%06x  %s%s" % (off, s[:160], mark))
            if not quiet:
                print("\n共 %d 条字符串，其中 %d 条可疑" % (len(rows), n_hit))
            return 0

        if cmd in ("lsb", "lsbscan"):
            rows = lsb_scan(path, max_bit=3 if cmd == "lsbscan" else 2)
            if not rows:
                print("没有找到可读的 LSB 数据（试了 rgb/rgba/r/g/b × 最低 2~3 位）")
                return 0
            for flen, ch, bit, data, frag in rows[:8]:
                print("通道=%-4s bit=%d  最长可读片段=%d 字节" % (ch, bit, flen))
                print("  %r" % frag[:200])
                subs = binwalk(data)
                if subs:
                    print("  内嵌: %s" % ", ".join(nm for _, nm in subs[:5]))
                if not quiet and flen < 40:
                    print("  （整个流开头 80 字节：%r）" % data[:80])
            return 0

        if cmd == "exif":
            info = exif_info(path)
            for k, v in info.items():
                print("  %-18s %s" % (k, v))
            return 0

        if cmd == "pngchunks":
            data = read(path)
            ch = png_chunks(data)
            known = {"IHDR", "PLTE", "IDAT", "IEND", "tRNS", "gAMA", "pHYs",
                     "sRGB", "tEXt", "zTXt", "iTXt", "bKGD", "cHRM", "iCCP",
                     "sBIT", "hIST", "sPLT", "tIME", "eXIf", "acTL", "fcTL", "fdAT"}
            for ctype, length, body in ch:
                flag = "" if ctype in known else "   <== 非标准块"
                extra = ""
                if ctype in ("tEXt", "iTXt", "zTXt"):
                    extra = "  " + repr(body[:120])
                print("  %-6s %6d%s%s" % (ctype, length, flag, extra))
            return 0

        if cmd == "zipinfo":
            data = read(path)
            ents = zip_entries(data)
            print("条目 %d 个：" % len(ents))
            for e in ents:
                enc = "  加密" if e["encrypted"] else ""
                print("  %-40s %8d → %8d  method=%d%s"
                      % (e["name"][:40], e["csize"], e["usize"], e["method"], enc))
            c = zip_comment(data)
            if c:
                print("\nZIP 注释: %r" % c[:500])
            fake = zip_fake_encrypt(ents, data)
            if fake:
                print("\n加密条目：")
                for f in fake:
                    print("  %s  local_flags=0x%04x central_flags=0x%04x  %s"
                          % (f["name"], f["local_flags"], f["central_flags"],
                             "标志不一致（疑似伪加密）" if f["inconsistent"] else ""))
            return 0

        if cmd == "unzip":
            data = read(path)
            ents = zip_entries(data)
            res = zip_extract(data, ents)
            dest = out or "./unzipped"
            os.makedirs(dest, exist_ok=True)
            dest_abs = os.path.realpath(dest)
            for name, content in res.items():
                if content is None:
                    print("  跳过（加密或无法解压）：%s" % name)
                    continue
                # 防 zip-slip：只 replace("..") 挡不住 Windows 的 C:\foo
                # （os.path.join 遇到绝对路径会直接丢掉前面的 dest）。
                safe = name.replace("..", "_").lstrip("/\\")
                safe = re.sub(r"^[A-Za-z]:", "_", safe)
                fp = os.path.realpath(os.path.join(dest_abs, safe))
                if fp != dest_abs and not fp.startswith(dest_abs + os.sep):
                    print("  跳过（路径越界）：%s" % name)
                    continue
                os.makedirs(os.path.dirname(fp) or dest_abs, exist_ok=True)
                with open(fp, "wb") as f:
                    f.write(content)
                print("  %s (%d 字节)" % (fp, len(content)))
            return 0

        if cmd == "qr":
            # 原来是 qr_scan(path, use_all or True)：use_all 是布尔，
            # False or True 恒等于 True，--all 形同虚设，而且每次都白跑两轮放大识别。
            outs = qr_scan(path, use_all)
            if not outs:
                print("没识别到二维码/条形码")
                return 0
            for o in outs:
                print(o)
            return 0

        if cmd == "spec":
            p = spectrum(path, out)
            print(p)
            return 0

        if cmd == "grid":
            res = grid_read(
                path,
                channel=opt("--channel", str, None),
                cols=opt("--cols", int, None),
                rows=opt("--rows", int, None),
                cell=opt("--cell", str, None),
                off=opt("--off", str, None),
                threshold=opt("--threshold", int, None),
                invert=True if "--invert" in argv else None,
                order=opt("--order", str, "row"),
            )
            print_grid(res, quiet=quiet)
            return 0

        if cmd == "meta":
            info = meta(path)
            for k, v in info.items():
                print("  %-12s %s" % (k, v))
            return 0

        if cmd == "hexdump":
            data = read(path)
            print(hexdump(data, opt("-l", int, 1024)))
            return 0

        print("未知子命令：%s" % cmd)
        print(__doc__)
        return 2

    except Exception as e:
        print("出错：%s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
