#!/usr/bin/env python3
"""XOR by hand, then the ctfkit helper.

XOR is the workhorse of CTF crypto because it is its own inverse:
``p ^ k ^ k == p``. The same operation encrypts and decrypts. A key shorter
than the data is cycled (repeating-key XOR).
"""
from ctfkit.encoding import xor

# By hand: zip the data with a cycled key.
def xor_by_hand(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

plain = b"attack at dawn"
key = b"KEY"
ct = xor_by_hand(plain, key)
print("cipher hex:", ct.hex())
print("decrypt   :", xor_by_hand(ct, key))

# ctfkit.encoding.xor does exactly this, and accepts str or bytes.
print("ctfkit xor:", xor(ct, key))
print("self-inverse:", xor(xor(plain, key), key) == plain)

# Single-byte key: the classic "XOR cipher" you brute-force in ch04.
one = xor(b"secret", b"\x2a")
print("single-byte:", one.hex(), "->", xor(one, b"\x2a"))
