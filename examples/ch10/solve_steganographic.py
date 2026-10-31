#!/usr/bin/env python3
"""Solve ImaginaryCTF `steganographic` -- invert the shipped generator.

Recon: the challenge ships `original.png`, `chall.png`, and `gen.py`.

Clue: read `gen.py`. For scattered pixels it does
`pixels[i,j] = (r + bit, g, b + 1, a)` -- so a modified pixel is exactly the
one whose BLUE channel went up by 1, and the flag bit is the RED-channel
difference. The flag is embedded MSB-first across those pixels (row-major).

We diff the two images: wherever blue increased by 1, read the red delta as a
bit; join the bits and decode as bytes.

Fetch first:  python challenges/fetch.py steganographic
"""
import os

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
BASE = os.path.join(REPO, "challenges", "steganographic", "challenge")


def main() -> None:
    orig = Image.open(os.path.join(BASE, "original.png")).load()
    chall = Image.open(os.path.join(BASE, "chall.png"))
    cpix = chall.load()
    bits = ""
    for i in range(chall.size[0]):
        for j in range(chall.size[1]):
            if cpix[i, j][2] - orig[i, j][2] == 1:
                bits += str(cpix[i, j][0] - orig[i, j][0])
    flag = bytes.fromhex(hex(int(bits, 2))[2:])
    print("FLAG:", flag.decode())


if __name__ == "__main__":
    main()
