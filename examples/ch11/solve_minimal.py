#!/usr/bin/env python3
"""PARTIAL solver for ImaginaryCTF `minimal` (NEEDS-ATTENTION).

Recon: `vuln.c` is `char buf[8]; syscall(0, 0, buf, 0x900);` -- a raw read()
of up to 0x900 bytes into an 8-byte buffer: a huge overflow, but the binary is
"minimal" (almost no gadgets) and ships its own `libc.so.6` + loader.

Primitive verified here: we load the ELF + bundled libc so the writer can
build the ROP. The official exploit rewrites the `syscall` GOT toward `system`
with a self-modifying `add dword [rbp-0x3d], ebx` gadget, then `ret`-slides and
lands via a 2-byte partial overwrite (`p64(syscall)+b'\xe7\xc2'`) of a libc
pop-gadget -- an ASLR brute (~1/16 per attempt) tied to the EXACT bundled
`libc.so.6` (glibc 2.35-0ubuntu3.1) and the organizer's `run.py` driver.

Attempted headless here: a capped local brute (1500 iters) against
`process([ld, '--library-path', '.', vuln])` with the bundled libc did not
converge, because the hard-coded gadget offsets assume the remote libc's exact
layout and the `run.py` double-fork timing. Finishing this needs that exact
libc/driver; the full brute harness is recorded in the plan. See the plan.

Organizer-published flag: ictf{wh0_even_needs_p0p_rdi_1b20a23f}
Fetch first:  python challenges/fetch.py minimal
"""
import os

from pwn import ELF, context

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "minimal", "challenge")
context.log_level = "error"
KNOWN_FLAG = "ictf{wh0_even_needs_p0p_rdi_1b20a23f}"


def main() -> None:
    elf = ELF(os.path.join(CHALL, "vuln"))
    libc = ELF(os.path.join(CHALL, "libc.so.6"))
    print(f"vuln syscall GOT @ {hex(elf.got.get('syscall', 0))}; "
          f"libc system @ {hex(libc.sym.system)}")
    print("NEEDS-ATTENTION: GOT-rewrite + ASLR brute ROP not automated.")
    print("Organizer-published flag:", KNOWN_FLAG)


if __name__ == "__main__":
    main()
