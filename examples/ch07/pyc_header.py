#!/usr/bin/env python3
"""The .pyc header: the magic number ties bytecode to one Python version.

A ``.pyc`` (PEP 552, Python 3.7+) is a 16-byte header followed by a
marshalled code object:

    bytes 0..4   magic number (interpreter version + b"\\r\\n")
    bytes 4..8   bit field (bit 0: hash-based pyc)
    bytes 8..16  timestamp+size, or an 8-byte source hash

If the magic does not match the interpreter you load it with, ``marshal``
chokes -- the usual reason a leaked ``.pyc`` "won't open". This is exactly why
the course pins Python 3.10: ``impossible`` ships a ``cpython-310`` ``.pyc``.
"""
import importlib.util
import struct

magic = importlib.util.MAGIC_NUMBER
print("this interpreter's magic:", magic.hex(), magic)

# Known magics for a few CPython releases (first 2 bytes are the version id).
KNOWN = {
    b"\x6f\x0d": "3.10",
    b"\xa7\x0d": "3.11",
    b"\xcb\x0d": "3.12",
}
tag = KNOWN.get(magic[:2], "unknown")
print("decoded version:", tag)

# A real .pyc body starts at offset 16; show the header fields.
header = magic + struct.pack("<I", 0) + struct.pack("<II", 0, 0)
print("header length:", len(header))
flags = struct.unpack_from("<I", header, 4)[0]
print("flags:", flags, "(bit0 set => hash-based)" if flags & 1 else "(timestamp-based)")
