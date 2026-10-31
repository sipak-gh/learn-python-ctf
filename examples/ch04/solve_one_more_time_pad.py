#!/usr/bin/env python3
"""Solve LA CTF 2024 `one-more-time-pad` -- known-plaintext on a repeating key.

Recon: `src/chall.py` XORs a known quote
("Long ago, the four nations lived together in harmony ...") against a
`cycle()` of a 32-byte key, and prints the hex ciphertext.

Clue: the plaintext is given in the source, and the key is used with
`itertools.cycle`, i.e. it repeats. XOR the ciphertext with the known
plaintext and the key falls out directly (it repeats every 32 bytes); the key
*is* the flag.

Fetch first:  python challenges/fetch.py one-more-time-pad
"""
import os
import re

from ctfkit.encoding import from_hex, xor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SRC = os.path.join(REPO, "challenges", "one-more-time-pad", "src", "chall.py")

PT = b"Long ago, the four nations lived together in harmony ..."


def main() -> None:
    source = open(SRC).read()
    ct_hex = re.search(r"#ct = ([0-9a-f]+)", source).group(1)
    ct = from_hex(ct_hex)
    keystream = xor(ct, PT)          # key repeated (cycle)
    key = keystream[:32]             # one period
    print("recovered key:", key.decode())
    print("FLAG:", key.decode())


if __name__ == "__main__":
    main()
