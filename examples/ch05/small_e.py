#!/usr/bin/env python3
"""Small-e / no-padding RSA: when c is a perfect e-th power.

If ``e`` is tiny (often 3) and the message is short, ``m^e`` can be smaller than
the modulus ``n``. Then ``c = m^e mod n`` never wraps -- ``c`` is just ``m^e``
as an ordinary integer, and the plaintext is the exact integer cube root. No
factoring, no private key. ``ctfkit.crypto.rsa_attack_small_e`` takes the
``e``-th root and checks it is exact.

The clue in a challenge: a published ``e = 3`` and a short secret.
"""
from Crypto.Util.number import getPrime

from ctfkit.crypto import rsa_attack_small_e
from ctfkit.encoding import bytes_to_long


def main() -> None:
    e = 3
    n = getPrime(1024) * getPrime(1024)        # a big modulus
    m = bytes_to_long(b"flag{cube_root_me}")   # short message
    c = pow(m, e, n)

    print("m^e < n :", m ** e < n)             # True -> no reduction happened
    flag = rsa_attack_small_e(c, e, n)
    print("recovered:", flag.decode())


if __name__ == "__main__":
    main()
