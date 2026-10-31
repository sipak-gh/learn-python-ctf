#!/usr/bin/env python3
"""Carve an embedded file out of a bigger blob by scanning for its magic.

A classic forensics move: a file (here a PNG) is hidden after some junk inside
another file. Find the signature, slice from there, and you have carved it out.
Real tools (`binwalk`, `foremost`) automate this; the core is `bytes.find`.
"""
from ctfkit.forensics import sniff_magic

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PNG_END = b"IEND\xaeB`\x82"  # the PNG footer chunk

# A pretend evidence file: junk, then a whole PNG, then more junk.
png = PNG_MAGIC + b"\x00\x00\x00\rIHDR....fake pixel data...." + PNG_END
blob = b"RIFF....decoy wav header...." + png + b"trailing garbage"

start = blob.find(PNG_MAGIC)
end = blob.find(PNG_END) + len(PNG_END)
carved = blob[start:end]

print("outer file looks like:", sniff_magic(blob))
print("found PNG at offset:", start)
print("carved bytes:", len(carved), "->", sniff_magic(carved))
