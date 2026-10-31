#!/usr/bin/env python3
"""Turn one leaked libc address into every address you need.

ASLR randomises where libc loads, but it shifts the whole library by one
constant. Leak any known symbol's runtime address, subtract its file offset,
and you have the load base -- then every other symbol is base + its offset.
`libc_base` even sanity-checks that the result is page-aligned.
"""
from ctfkit.pwn import libc_base, resolve

# Offsets you read once from the provided libc (e.g. `libc.sym.puts`).
PUTS_OFF = 0x80E50
SYSTEM_OFF = 0x50D60
BINSH_OFF = 0x1D8678

# At runtime the program leaks puts()'s real address.
leaked_puts = 0x7F3C2A88E50

base = libc_base(leaked_puts, PUTS_OFF)
print("libc base :", hex(base))
print("system()  :", hex(resolve(base, SYSTEM_OFF)))
print('"/bin/sh" :', hex(resolve(base, BINSH_OFF)))

# A wrong offset yields an unaligned base -- libc_base refuses it.
try:
    libc_base(leaked_puts, 0x80E51)
except ValueError as exc:
    print("bad offset caught:", exc)
