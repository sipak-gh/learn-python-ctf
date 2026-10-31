#!/usr/bin/env python3
"""Find the overflow offset with a de Bruijn (cyclic) pattern.

Instead of counting bytes by hand, send a pattern where every 4-byte window is
unique. Whatever lands in the saved return address is one of those windows, so
`cyclic_find` tells you its exact offset -- the number of bytes before you
control the return address.
"""
from ctfkit.pwn import cyclic, cyclic_find

pattern = cyclic(64)
print("pattern:", pattern.decode())

# Pretend the program crashed and the saved return address held these 4 bytes
# (this is what you would read from a core dump or $eip in gdb).
crashed_with = pattern[40:44]
print("bytes in return address:", crashed_with.decode())
print("offset to return address:", cyclic_find(crashed_with))

# You usually read the value as an integer off the stack -- that works too.
leaked_int = int.from_bytes(crashed_with, "little")
print("same answer from the int:", cyclic_find(leaked_int))
