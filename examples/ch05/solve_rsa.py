#!/usr/bin/env python3
"""Solve ImaginaryCTF 2023 `rsa` -- you were handed the private key.

Recon: the challenge ships `public.pem`, `private.pem`, and `flag.enc`.

Clue: having the *private* key means there is no attack. This is the "learn
the RSA machinery and PEM parsing" warm-up: import the key, read d and n, and
compute m = c^d mod n.

Fetch first:  python challenges/fetch.py rsa
"""
import os

from Crypto.PublicKey import RSA

from ctfkit.crypto import rsa_decrypt
from ctfkit.encoding import bytes_to_long

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
BASE = os.path.join(REPO, "challenges", "rsa", "challenge")


def main() -> None:
    key = RSA.importKey(open(os.path.join(BASE, "private.pem"), "rb").read())
    c = bytes_to_long(open(os.path.join(BASE, "flag.enc"), "rb").read())
    flag = rsa_decrypt(c, key.d, key.n)
    print("FLAG:", flag.decode())


if __name__ == "__main__":
    main()
