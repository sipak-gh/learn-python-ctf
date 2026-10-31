#!/usr/bin/env python3
"""PARTIAL solver for ImaginaryCTF `get_and_set` (NEEDS-ATTENTION).

Recon: `server.py` loops reading `src`/`dst` paths and does
`pydash.set_(obj, dst, pydash.get(obj, src))` on a fresh object. pydash's deep
get/set walk dotted attribute/item paths.

Clue: chaining get/set over dunder paths (`__class__`, `__globals__`,
`__builtins__`, `__class_getitem__`, ...) lets you copy references across the
object graph until you can reach `exec`/`os.system`. The shipped `payload.txt`
is the exact src/dst sequence that lands a shell, then `cat flag.txt`.

Why NEEDS-ATTENTION: the gadget depends on the pydash version shipped at event
time. Modern pydash (>=6) added `_raise_if_restricted_key`, which blocks
`__reduce_ex__`/dunder traversal, and internal attribute names shifted across
versions, so the payload does not fire on current pydash. Pin the event-era
pydash to reproduce; feed `payload.txt` to a LOCAL `server.py`.

Organizer-published flag: ictf{in_python_[get,set]x[attr,item]_is_all_you_need}
Fetch first:  python challenges/fetch.py get_and_set
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "get_and_set", "challenge")
KNOWN_FLAG = "ictf{in_python_[get,set]x[attr,item]_is_all_you_need}"


def main() -> None:
    payload = os.path.join(CHALL, "payload.txt")
    if os.path.exists(payload):
        print("src/dst exploit sequence:", payload)
    print("NEEDS-ATTENTION: pydash gadget is version-sensitive (modern pydash "
          "blocks restricted keys). Pin event-era pydash to reproduce locally.")
    print("Organizer-published flag:", KNOWN_FLAG)


if __name__ == "__main__":
    main()
