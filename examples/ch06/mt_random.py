#!/usr/bin/env python3
"""random.random() consumes two 32-bit words -- which matters for bit leaks.

CPython builds a 53-bit float from *two* MT outputs: ``a = next>>5`` (27 bits)
and ``b = next>>6`` (26 bits), combined as ``(a*2**26 + b) / 2**53``.
``ctfkit.crypto.MT19937`` reproduces this in ``.random()`` and seeds exactly like
CPython in ``from_seed``, so a cloned generator matches the real stream.

Why this detail matters: ``encrypted-mail`` leaks only ``round(random.random())``
-- a *single* bit per call, after consuming two whole state words. That is why
you cannot simply untemper it; you need a linear (GF(2)) solve over many such
bits. This example shows the float-to-word relationship behind that fact.
"""
import random

from ctfkit.crypto import MT19937


def main() -> None:
    # Our MT seeded like CPython reproduces random.random() exactly.
    mine = MT19937.from_seed(2024)
    random.seed(2024)
    ours = [mine.random() for _ in range(3)]
    theirs = [random.random() for _ in range(3)]
    print("floats match:", ours == theirs)

    # Each random() eats two 32-bit words; round() then keeps just one bit.
    mt = MT19937.from_seed(2024)
    f = mt.random()
    print("one random() =", f, "-> round ->", round(f))
    print("that call consumed 2 of the 624 state words")


if __name__ == "__main__":
    main()
