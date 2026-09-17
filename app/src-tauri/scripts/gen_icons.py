#!/usr/bin/env python3
"""Генерация PNG-иконок Ligament VPN (чистый stdlib: zlib + struct).

icon.png        — 512x512: скруглённый синий квадрат с белым «щитом»
tray-*.png      — 32x32: цветной круг (серый/жёлтый/зелёный) для статусов трея
"""
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "icons")


def png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def write_png(path: str, w: int, h: int, pixels: list[list[list[int]]]) -> None:
    raw = b"".join(
        b"\x00" + b"".join(bytes(px) for px in row) for row in pixels
    )
    png = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
        + png_chunk(b"IDAT", zlib.compress(raw, 9))
        + png_chunk(b"IEND", b"")
    )
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(png)
    print("ok:", path)


def rounded_square(size: int, color, radius_ratio=0.22):
    """Скруглённый квадрат с простым белым щитом (круг + треугольник)."""
    r = int(size * radius_ratio)
    cx = cy = size / 2
    shield_top_r = size * 0.26          # «замок» — верхняя часть щита
    pixels = []
    for y in range(size):
        row = []
        for x in range(size):
            # скругление углов
            in_corner = (
                (x < r and y < r and (x - r) ** 2 + (y - r) ** 2 > r * r)
                or (x >= size - r and y < r and (x - (size - r - 1)) ** 2 + (y - r) ** 2 > r * r)
                or (x < r and y >= size - r and (x - r) ** 2 + (y - (size - r - 1)) ** 2 > r * r)
                or (x >= size - r and y >= size - r and (x - (size - r - 1)) ** 2 + (y - (size - r - 1)) ** 2 > r * r)
            )
            if in_corner:
                row.append([0, 0, 0, 0])
                continue
            # щит: круг сверху + сужающийся низ
            dy = y - (cy - size * 0.08)
            dx = x - cx
            in_circle = dx * dx + dy * dy < shield_top_r * shield_top_r
            in_tail = abs(dx) < shield_top_r * (1 - max(0.0, dy) / (size * 0.38)) and 0 <= dy <= size * 0.38
            if in_circle or in_tail:
                row.append([255, 255, 255, 255])
            else:
                row.append(list(color) + [255])
        pixels.append(row)
    return pixels


def circle(size: int, color):
    cx = cy = (size - 1) / 2
    r = size * 0.42
    pixels = []
    for y in range(size):
        row = []
        for x in range(size):
            dx, dy = x - cx, y - cy
            if dx * dx + dy * dy <= r * r:
                row.append(list(color) + [255])
            else:
                row.append([0, 0, 0, 0])
        pixels.append(row)
    return pixels


BLUE = (47, 111, 237)      # #2F6FED
GRAY = (154, 163, 175)     # #9AA3AF
YELLOW = (245, 166, 35)    # #F5A623
GREEN = (52, 199, 89)      # #34C759

write_png(os.path.join(OUT, "icon.png"), 512, 512, rounded_square(512, BLUE))
write_png(os.path.join(OUT, "tray-gray.png"), 32, 32, circle(32, GRAY))
write_png(os.path.join(OUT, "tray-yellow.png"), 32, 32, circle(32, YELLOW))
write_png(os.path.join(OUT, "tray-green.png"), 32, 32, circle(32, GREEN))
print("done")

# --- icon.ico (мультисайзовый, PNG-записи; см. отдельный генератор в истории) ---
# ICO уже сгенерирован и закоммичен (16..256); при необходимости пересоздания
# используйте: python3 - <<'PY'  (тот же алгоритм, что в CI-фиксе 2026-09-17)
import io

def _load_rgba(path):
    data = open(path, "rb").read()
    pos, idat, w = 8, b"", 0
    while pos < len(data):
        ln = int.from_bytes(data[pos:pos+4], "big")
        tag = data[pos+4:pos+8]
        if tag == b"IHDR":
            w, h = int.from_bytes(data[pos+8:pos+12], "big"), int.from_bytes(data[pos+12:pos+16], "big")
        elif tag == b"IDAT":
            idat += data[pos+8:pos+8+ln]
        pos += 12 + ln
    raw = zlib.decompress(idat)
    px, stride = [], w * 4 + 1
    for y in range(h):
        row = raw[y*stride+1:(y+1)*stride]
        px.append([list(row[x*4:(x+1)*4]) for x in range(w)])
    return w, h, px

def _png_bytes(w, h, px):
    raw = b"".join(b"\x00" + b"".join(bytes(p) for p in row) for row in px)
    def ch(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + ch(b"IDAT", zlib.compress(raw, 9)) + ch(b"IEND", b""))

_W, _H, _PX = _load_rgba(os.path.join(OUT, "icon.png"))
_imgs = []
for _s in (16, 24, 32, 48, 64, 128, 256):
    _d = [[_PX[min(_H-1, y*_H//_s)][min(_W-1, x*_W//_s)] for x in range(_s)] for y in range(_s)]
    _imgs.append((_s, _png_bytes(_s, _s, _d)))
_hdr = struct.pack("<HHH", 0, 1, len(_imgs))
_dir, _blob, _off = b"", b"", 6 + 16 * len(_imgs)
for _s, _b in _imgs:
    _dir += struct.pack("<BBBBHHII", _s % 256, _s % 256, 0, 0, 1, 32, len(_b), _off)
    _blob += _b
    _off += len(_b)
open(os.path.join(OUT, "icon.ico"), "wb").write(_hdr + _dir + _blob)
print("ok:", os.path.join(OUT, "icon.ico"))
