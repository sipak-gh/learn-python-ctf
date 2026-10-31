#!/usr/bin/env python3
"""Hide a message in the low bit of each pixel, then read it back.

LSB stego changes the least-significant bit of colour channels -- invisible to
the eye, since it shifts a value by at most 1. `ctfkit.forensics.lsb_extract`
reads bit plane 0 of the chosen channels and packs the bits into bytes.

This builds a tiny image, embeds "flag{lsb}" MSB-first in the red channel,
then extracts it.
"""
import os

import numpy as np
from PIL import Image

from ctfkit.forensics import lsb_extract

SCRATCH = os.path.join(os.path.dirname(__file__), "_scratch")
os.makedirs(SCRATCH, exist_ok=True)
path = os.path.join(SCRATCH, "lsb.png")

message = b"flag{lsb}"
bits = [(byte >> i) & 1 for byte in message for i in range(7, -1, -1)]

# A flat grey image; write each message bit into the low bit of one red pixel.
pixels = np.full((1, len(bits), 3), 128, dtype=np.uint8)
for i, bit in enumerate(bits):
    pixels[0, i, 0] = (128 & ~1) | bit  # clear low bit, set it to our bit

Image.fromarray(pixels, "RGB").save(path)

recovered = lsb_extract(path, channels="R", plane=0)
print("embedded :", message)
print("recovered:", recovered[: len(message)])
