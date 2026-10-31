#!/usr/bin/env python3
"""Factoring weak moduli: Fermat for close primes, sympy for small ones.

RSA's security rests on ``n`` being hard to factor. Two common CTF weaknesses
hand it to you:

* **Close primes.** If ``p`` and ``q`` are near each other (e.g. two halves of a
  flag, or ``q = nextprime(p)``), Fermat's method writes ``n = a^2 - b^2`` and
  finds them in a handful of steps. ``ctfkit.crypto.factor_fermat``.
* **Small ``n``.** A short modulus just factors. ``sympy.factorint`` returns the
  full factorisation; the practitioner tool you reach for when ``n`` is small.

Either way, once you have ``p`` and ``q`` you rebuild ``phi`` and decrypt.
"""
from sympy import factorint, nextprime

from ctfkit.crypto import factor_fermat


def main() -> None:
    # Close primes -> Fermat finds them fast.
    p = nextprime(10 ** 30)
    q = nextprime(p)                   # adjacent prime: tiny gap
    n = p * q
    fp, fq = factor_fermat(n)
    print("Fermat  :", fp, fq, " ok=", {fp, fq} == {int(p), int(q)})

    # Small modulus -> just factor it.
    small_n = 0xC0FFEE1234567
    print("factorint:", factorint(small_n))


if __name__ == "__main__":
    main()
