#!/usr/bin/env python3
"""Pack and unpack integers the way the CPU sees them.

Exploits are addresses pretending to be text. x86-64 is little-endian, so the
address 0x401196 travels as the bytes 96 11 40 00 00 00 00 00. `ctfkit.pwn`
wraps `struct` so you never fumble the byte order.
"""
from ctfkit.pwn import p32, p64, u32, u64

addr = 0x401196
print("p64(0x401196) =", p64(addr).hex(" "))
print("u64 round-trip:", hex(u64(p64(addr))))
print("p32(0xdeadbeef) =", p32(0xDEADBEEF).hex(" "))

# A short leak read off the stack is NUL-padded before unpacking.
leak = b"\x96\x11\x40"       # only three bytes came back
print("padded u64 of a 3-byte leak:", hex(u64(leak)))
