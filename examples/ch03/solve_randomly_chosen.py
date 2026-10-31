#!/usr/bin/env python3
"""Solve DownUnderCTF 2023 `randomly-chosen` -- small seed + reversible choices.

Recon: `src/randomly-chosen.py` seeds `random` with `randrange(0, 1337)`
(small!) then prints `random.choices(flag, k=len(flag)*5)`.

Clue (from HINTS.md): the seed space is tiny -- brute all 1337 values. For a
guessed seed we replay the PRNG: `random.choices` draws each index as
`int(random() * len(flag))`, so output[j] == flag[index_j]. That lets us fill
the flag array from the scrambled output. The flag format `DUCTF{...}`
confirms the right seed.

We don't know len(flag) up front, but len(output) == 5*len(flag), so L is
fixed by the output length.

Fetch first:  python challenges/fetch.py randomly-chosen
"""
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(REPO, "challenges", "randomly-chosen", "src", "output.txt")


def try_seed(seed, out, length):
    random.seed(seed)
    flag = [None] * length
    # mirror random.choices(population, k): index = int(random()*length)
    for ch in out:
        idx = int(random.random() * length)
        if flag[idx] is None:
            flag[idx] = ch
        elif flag[idx] != ch:
            return None
    if None in flag:
        return None
    return "".join(flag)


def main() -> None:
    out = open(OUT).read().strip()
    length = len(out) // 5
    for seed in range(1337):
        cand = try_seed(seed, out, length)
        if cand and cand.startswith("DUCTF{"):
            print("seed =", seed)
            print("FLAG:", cand)
            return
    print("no seed found")


if __name__ == "__main__":
    main()
