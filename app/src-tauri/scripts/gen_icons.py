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
