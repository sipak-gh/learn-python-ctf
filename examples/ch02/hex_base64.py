#!/usr/bin/env python3
"""Hex and base64, by hand and with the standard library.

Both turn raw bytes into an ASCII-safe string so binary survives a text
channel. Hex doubles the size (2 chars/byte); base64 adds ~33% (4 chars per
3 bytes). You convert constantly between these and raw bytes.
"""
import base64
import binascii

raw = b"\xde\xad\xbe\xef"

# Hex: bytes.hex() and bytes.fromhex() are the idiomatic pair.
h = raw.hex()
print("hex:", h)
print("round-trip:", bytes.fromhex(h) == raw)

# fromhex ignores spaces, so you can paste a dump straight in.
print("spaced:", bytes.fromhex("de ad be ef"))

# binascii does the same with a different name (you'll see both in writeups).
print("binascii:", binascii.hexlify(raw).decode())

# Base64: standard and url-safe alphabets.
msg = b"clue>hypothesis>flag"
enc = base64.b64encode(msg)
print("b64:", enc.decode())
print("b64 decode:", base64.b64decode(enc))

# CTF data often drops the '=' padding; restore it before decoding.
unpadded = "aGVsbG8"          # "hello" without padding
padded = unpadded + "=" * (-len(unpadded) % 4)
print("repadded:", base64.b64decode(padded))
