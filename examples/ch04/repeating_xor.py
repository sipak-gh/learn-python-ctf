#!/usr/bin/env python3
"""Break repeating-key XOR: find the key length, then solve each column.

Repeating-key (Vigenere-style) XOR cycles a multi-byte key over the plaintext.
Two steps break it:

1. Guess the key length. The right length makes blocks line up, so their
   normalised Hamming distance (bit differences per byte) is smallest.
   ``ctfkit.crypto.guess_keysize`` ranks candidates this way.
2. Split the ciphertext into that many columns. Every byte in a column used the
   *same* key byte, so each column is a single-byte XOR you already know how to
   break. ``break_repeating_key_xor`` stitches the per-column keys together.
"""
from ctfkit.crypto import break_repeating_key_xor, guess_keysize
from ctfkit.encoding import xor

PLAINTEXT = (
    b"The clue-driven method turns a pile of files into a flag: recon, then "
    b"clues, then a hypothesis you actually test. Repeating-key XOR falls to "
    b"frequency analysis one column at a time, which is why practitioners reach "
    b"for a stream cipher or a real KDF instead of a short cycled key."
)
KEY = b"CTFKIT"


def main() -> None:
    ct = xor(PLAINTEXT, KEY)
    print("keysize candidates:", guess_keysize(ct))
    found_key, recovered = break_repeating_key_xor(ct)
    print("recovered key     :", found_key)
    print("plaintext starts  :", recovered[:48].decode())
    print("exact match       :", recovered == PLAINTEXT)


if __name__ == "__main__":
    main()
