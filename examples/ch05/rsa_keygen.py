#!/usr/bin/env python3
"""Textbook RSA in a dozen lines: keygen, encrypt, decrypt, by hand.

RSA is three numbers and two `pow` calls:

* Pick two primes ``p, q``; set ``n = p*q`` and ``phi = (p-1)*(q-1)``.
* Pick a public exponent ``e`` (usually 65537) coprime to ``phi``; the private
  exponent is ``d = e^{-1} mod phi``.
* Encrypt a message integer ``m`` with ``c = m^e mod n``; decrypt with
  ``m = c^d mod n``.

Python's built-in ``pow(base, exp, mod)`` does modular exponentiation for
thousand-bit numbers instantly, so "RSA from scratch" really is this short.
``ctfkit.encoding`` converts between the flag bytes and the integer ``m``.
"""
from Crypto.Util.number import getPrime

from ctfkit.encoding import bytes_to_long, long_to_bytes


def main() -> None:
    p, q = getPrime(512), getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)

    m = bytes_to_long(b"flag{textbook_rsa_is_just_two_pows}")
    c = pow(m, e, n)
    recovered = long_to_bytes(pow(c, d, n))

    print("n bits    :", n.bit_length())
    print("ciphertext:", hex(c)[:50], "...")
    print("recovered :", recovered.decode())


if __name__ == "__main__":
    main()
