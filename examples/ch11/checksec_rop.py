#!/usr/bin/env python3
"""Inspect a binary's defenses and find gadgets with pwntools.

Before writing an exploit you read the binary: which mitigations are on, where
`win()` lives, what gadgets exist. `ELF` parses it; `checksec()` reports NX /
PIE / canary / RELRO; `ROP` searches for gadgets like a bare `ret` (needed for
16-byte stack alignment before a `call`).

This compiles a throwaway vulnerable binary so the example is self-contained.
"""
import warnings

warnings.filterwarnings("ignore")  # hide an unrelated setuptools deprecation note

import os
import subprocess

from pwn import ELF, ROP, context

context.log_level = "error"

SCRATCH = os.path.join(os.path.dirname(__file__), "_scratch")
os.makedirs(SCRATCH, exist_ok=True)
src = os.path.join(SCRATCH, "demo.c")
binp = os.path.join(SCRATCH, "demo")

with open(src, "w") as f:
    f.write(
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "void win(){ system(\"/bin/sh\"); }\n"
        "int main(){ char b[64]; gets(b); }\n"
    )
subprocess.run(
    ["gcc", src, "-o", binp, "-fno-stack-protector", "-no-pie"],
    check=True, stderr=subprocess.DEVNULL,
)

elf = ELF(binp)
print(elf.checksec())
print("win()  @", hex(elf.sym.win))
print("main() @", hex(elf.sym.main))

ret = ROP(elf).find_gadget(["ret"])[0]
print("bare ret gadget @", hex(ret))
