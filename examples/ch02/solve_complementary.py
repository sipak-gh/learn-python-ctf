#!/usr/bin/env python3
"""Solve DownUnderCTF 2023 `complementary` -- "RSA" that is just factoring.

Recon: `complementary.py` splits the flag in half, turns each half into an
integer with `int.from_bytes`, and prints only the product `n = m1 * m2`.

Clue: there is no modulus, no exponent -- the whole "crypto" is a single
multiplication of two numbers (the two flag halves). So this is a factoring
problem, not RSA.

Dead end: Fermat factorisation (ctfkit.factor_fermat) assumes the two factors
are *close*. Here the halves differ in size (37-byte flag -> 18 and 19 bytes),
so Fermat does not converge. But the halves are ASCII text, hence composite
and fairly smooth, so `sympy.factorint` fully factors `n` quickly. Then we
search the ways to split the prime factors into two groups until both groups
decode to printable bytes that form `DUCTF{...}`.

Fetch first:  python challenges/fetch.py complementary
"""
import itertools
import os
from functools import reduce

import sympy

from ctfkit.encoding import long_to_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTPUT = os.path.join(REPO, "challenges", "complementary", "src", "output.txt")


def main() -> None:
    n = int(open(OUTPUT).read().strip())
    factor_counts = sympy.factorint(n)
    primes = []
    for prime, exp in factor_counts.items():
        primes += [prime] * exp
    print(f"n has {len(primes)} prime factors; searching splits...")

    seen = set()
    for r in range(1, len(primes)):
        for combo in itertools.combinations(range(len(primes)), r):
            m1 = reduce(lambda a, i: a * primes[i], combo, 1)
            if m1 in seen:
                continue
            seen.add(m1)
            m2 = n // m1
            flag = long_to_bytes(m1) + long_to_bytes(m2)
            if flag.startswith(b"DUCTF{") and flag.endswith(b"}") and flag.isascii():
                print("FLAG:", flag.decode())
                return
    raise SystemExit("no printable split found")


if __name__ == "__main__":
    main()
