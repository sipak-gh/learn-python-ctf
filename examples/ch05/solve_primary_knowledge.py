#!/usr/bin/env python3
"""Solve HTB Cyber Apocalypse 2024 `[Very Easy] Primary Knowledge`.

Recon: `output.txt` gives n, e, c. Normal RSA needs you to factor n into two
primes p, q to get phi = (p-1)(q-1). Here, try factoring and you notice n is
itself *prime*.

Clue: a prime modulus. Then the group has order phi = n - 1 directly -- no
factoring needed. Compute d = e^{-1} mod (n-1) and decrypt.

(The challenge repo is an official HTB write-up: the numbers live in
output.txt; there is no separate source.py, which is fine -- output.txt is all
we need.)

Fetch first:  python challenges/fetch.py primary-knowledge
"""
import os

from sympy import isprime

from ctfkit.crypto import rsa_attack_prime_modulus

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTPUT = os.path.join(REPO, "challenges", "primary-knowledge", "htb", "output.txt")


def main() -> None:
    env: dict = {}
    exec(open(OUTPUT).read(), env)  # defines n, e, c
    n, e, c = env["n"], env["e"], env["c"]
    assert isprime(n), "clue was wrong: n is not prime"
    print("n is prime -> phi = n - 1, no factoring needed")
    flag = rsa_attack_prime_modulus(c, e, n)
    print("FLAG:", flag.decode())


if __name__ == "__main__":
    main()
