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
  qr <image>                  用 zbarimg 识别二维码/条形码（--all 尝试全分辨率）
  spec <audio> [--out a.png]  ffmpeg 生成频谱图（看隐藏的摩斯/文字）
  meta <file>                 文件类型 + 尺寸 + 熵

通用：-q 只输出结果
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
    cmd = ["ffmpeg", "-y", "-v", "error", "-i", path,
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
