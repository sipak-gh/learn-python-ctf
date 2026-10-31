import struct

import pytest

from ctfkit import forensics as fx


def test_sniff_magic_known_and_unknown():
    assert fx.sniff_magic(b"\x89PNG\r\n\x1a\n....") == "PNG image"
    assert fx.sniff_magic(b"PK\x03\x04rest") == "ZIP / Office / JAR"
    assert fx.sniff_magic(b"not a known magic") is None


def test_lsb_bits_packs_msb_first():
    bits = [0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0]  # 'A', 'B'
    assert fx.lsb_bits(bits) == b"AB"


def test_lsb_extract_roundtrip(tmp_path):
    from PIL import Image

    message = b"flag{lsb}"
    bits = []
    for byte in message:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    # one channel (R), one bit per pixel
    pixels = []
    for i, b in enumerate(bits):
        pixels.append(((200 & ~1) | b, 0, 0))
    # pad to a rectangle
    while len(pixels) < 16:
        pixels.append((0, 0, 0))
    img = Image.new("RGB", (len(pixels), 1))
    img.putdata(pixels)
    path = tmp_path / "s.png"
    img.save(path)
    out = fx.lsb_extract(str(path), channels="R", plane=0)
    assert out.startswith(message)
