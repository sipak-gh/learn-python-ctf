#!/usr/bin/env python3
"""Integers <-> bytes, and modular exponentiation.

Crypto treats a message as one big integer. Python's ``int`` is unbounded,
so a 256-byte RSA block is just a number you can multiply and exponentiate.

* ``int.from_bytes(b, "big")`` reads bytes as a base-256 number.
* ``n.to_bytes(length, "big")`` writes it back.
* ``pow(base, exp, mod)`` is fast modular exponentiation -- the heart of RSA.
"""

flag = b"DUCTF{n}"
n = int.from_bytes(flag, "big")
print("as int:", n)

# Back to bytes: you must give a length (enough to hold the number).
length = (n.bit_length() + 7) // 8
print("as bytes:", n.to_bytes(length, "big"))

# A zero-length edge case: to_bytes needs room, from_bytes of b"" is 0.
print("empty ->", int.from_bytes(b"", "big"))

# pow with three args never builds the huge intermediate -- O(log exp).
base, exp, mod = 7, 1234567, 100003
print("pow(7, 1234567, 100003) =", pow(base, exp, mod))

# Modular inverse (Python 3.8+): pow(a, -1, m).
print("inverse of 3 mod 100003:", pow(3, -1, 100003))
