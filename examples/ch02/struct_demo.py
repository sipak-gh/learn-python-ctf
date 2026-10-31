#!/usr/bin/env python3
"""struct: pack and unpack fixed-width binary fields.

File formats and binary protocols are structs of fixed-width integers.
``struct`` converts between Python ints and their byte layout. The format
string picks size and byte order:

* ``<`` little-endian, ``>`` big-endian (network order).
* ``I`` uint32, ``H`` uint16, ``B`` uint8, ``Q`` uint64.
"""
import struct

# Pack three fields into a little-endian header.
header = struct.pack("<IHB", 0xDEADBEEF, 0x1234, 7)
print("packed:", header.hex())

# Unpack them back. unpack always returns a tuple.
magic, ver, flags = struct.unpack("<IHB", header)
print(f"magic={magic:#x} ver={ver:#x} flags={flags}")

# Byte order matters: same bytes, different endianness.
print("LE:", struct.unpack("<I", b"\x01\x00\x00\x00")[0])
print("BE:", struct.unpack(">I", b"\x01\x00\x00\x00")[0])

# A PNG's width/height live as two big-endian uint32 at offset 16.
png_ihdr = bytes.fromhex("0000010000000080")  # width=256, height=128
width, height = struct.unpack(">II", png_ihdr)
print("png size:", width, "x", height)
