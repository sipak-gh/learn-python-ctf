#!/usr/bin/env python3
"""PARTIAL solver for ImaginaryCTF `pycrib` (NEEDS-ATTENTION).

Recon: `main.py` `exec()`s one input line but only allows lowercase letters +
whitespace, and nulls out many `sys.modules` (heap/imp/marshal/code/func/...).
At the end it calls `exit(b)` after `del sys`.

Clue: lowercase+whitespace still allows `from os import system as exit` and
rebinding names. The published cheese reuses `main.inp` (your own input string)
as the argument to `os.system`, making the line a bash/python polyglot via an
embedded carriage return (`\r`). The exploit therefore depends on the kctf
`run.sh` + shell environment to interpret the polyglot, so it is reproduced
rather than fully automated here; see the plan and the shipped `solve.py`/`t.py`.

Payload idea (all lowercase+whitespace):
    from main import inp as b\rfrom os import system as exit

Organizer-published flag: ictf{bash_python_polygl0t?_or_cheese_810a32fb}
Fetch first:  python challenges/fetch.py pycrib
"""
KNOWN_FLAG = "ictf{bash_python_polygl0t?_or_cheese_810a32fb}"


def main() -> None:
    print("NEEDS-ATTENTION: bash/python polyglot cheese needs the kctf run.sh env.")
    print("See challenges/pycrib/challenge/solve.py and t.py for the payloads.")
    print("Organizer-published flag:", KNOWN_FLAG)


if __name__ == "__main__":
    main()
