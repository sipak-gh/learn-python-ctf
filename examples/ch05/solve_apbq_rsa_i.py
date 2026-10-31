#!/usr/bin/env python3
"""Solve DownUnderCTF 2024 `apbq-rsa-i` -- leaking a*p + b*q.

Recon: `output.txt` gives n, c (standard RSA with e=65537) and two "hints".
Reading `src/apbq-rsa-i.py` shows each hint is `a*p + b*q` where
`a < 2**12` (tiny) and `b < 2**312` (huge).

Clue: the two small coefficients a0, a1 are brute-forceable (4096 each). For
the right pair, the combination

    a1 * hint0 - a0 * hint1
      = a1*(a0 p + b0 q) - a0*(a1 p + b1 q)
      = (a1 b0 - a0 b1) q

is a multiple of q, so gcd(that, n) reveals q. Classic "gcd is a good
algorithm for the toolbox". We then divide out the small cofactor and do
textbook RSA.

Fetch first:  python challenges/fetch.py apbq-rsa-i
"""
import os
from math import gcd

from ctfkit.encoding import long_to_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTPUT = os.path.join(REPO, "challenges", "apbq-rsa-i", "src", "output.txt")
E = 0x10001


def recover_q(n, h0, h1, bound=4096):
    for a1 in range(1, bound):
        a1h0 = a1 * h0
        for a0 in range(1, bound):
            g = gcd(a1h0 - a0 * h1, n)
            if 1 < g < n:
                return g
    raise RuntimeError("no coefficient pair found")


def main() -> None:
    env: dict = {}
    exec(open(OUTPUT).read(), env)  # defines n, c, hints
    n, c, hints = env["n"], env["c"], env["hints"]
    kq = recover_q(n, hints[0], hints[1])
    for i in range(2 ** 16, 1, -1):  # strip the (a1 b0 - a0 b1) cofactor
        while kq % i == 0 and kq // i > 1 and n % (kq // i) == 0:
            kq //= i
    q = kq
    p = n // q
    assert p * q == n, "factorisation failed"
    d = pow(E, -1, (p - 1) * (q - 1))
    m = pow(c, d, n)
    print("FLAG:", long_to_bytes(m).decode())


if __name__ == "__main__":
    main()
