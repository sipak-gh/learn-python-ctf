#!/usr/bin/env python3
"""Modular arithmetic for RSA: inverses with the extended Euclidean algorithm.

RSA lives in modular arithmetic. The one non-obvious piece is the *modular
inverse*: given ``e`` and a modulus ``m``, find ``d`` with ``e*d == 1 (mod m)``.
That ``d`` is the private exponent. The extended Euclidean algorithm computes it
(``ctfkit.crypto.egcd`` / ``modinv``), and since Python 3.8 ``pow(e, -1, m)``
does the same in one call -- we show both and check they agree.
"""
from ctfkit.crypto import egcd, modinv


def main() -> None:
    e, phi = 65537, 3120
    g, x, y = egcd(e, phi)
    print(f"egcd({e}, {phi}) = (g={g}, x={x}, y={y})")
    print(f"check: {e}*{x} + {phi}*{y} = {e * x + phi * y}")

    d1 = modinv(e, phi)
    d2 = pow(e, -1, phi)          # stdlib shortcut, Python 3.8+
    print(f"modinv      = {d1}")
    print(f"pow(e,-1,m) = {d2}")
    print(f"e*d mod phi = {e * d1 % phi}")


if __name__ == "__main__":
    main()
