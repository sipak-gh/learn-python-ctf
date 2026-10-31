#!/usr/bin/env python3
"""Caesar cipher: shift every letter by a fixed amount, then brute all 26 shifts.

A Caesar cipher is the simplest substitution: each letter moves N places along
the alphabet. There are only 25 useful keys, so you never "crack" it -- you
print all 26 rotations and read the one that is English. `ctfkit.encoding.rot`
(from Chapter 2) does one rotation; here we wrap it in a brute-force loop.
"""
from ctfkit.encoding import rot

CIPHERTEXT = "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"  # shifted by 3


def brute(text: str):
    for n in range(26):
        yield n, rot(text, n)


def main() -> None:
    for n, candidate in brute(CIPHERTEXT):
        print(f"{n:2d}: {candidate}")


if __name__ == "__main__":
    main()
