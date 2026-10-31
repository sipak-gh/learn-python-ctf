#!/usr/bin/env python3
"""Seeding and seed brute force: a small seed is a small keyspace.

``random.seed(x)`` makes the whole stream a deterministic function of ``x``.
Re-seed with the same value and you get the same numbers -- great for
reproducibility, fatal for security. If a challenge seeds from something small
(a 16-bit value, a PID, a timestamp), you just try every seed offline and keep
the one whose output matches what you observed. That is the whole idea behind
``randomly-chosen`` in Chapter 3, generalised here.
"""
import random


def main() -> None:
    # Determinism: same seed -> same stream.
    random.seed(1337)
    a = [random.randint(0, 999) for _ in range(5)]
    random.seed(1337)
    b = [random.randint(0, 999) for _ in range(5)]
    print("reproducible:", a == b, a)

    # A service seeds with a secret 16-bit value and leaks three outputs.
    secret = 0xBEEF & 0xFFFF
    random.seed(secret)
    leak = [random.getrandbits(16) for _ in range(3)]

    # Brute all 65536 seeds offline until the leak matches.
    for guess in range(1 << 16):
        random.seed(guess)
        if [random.getrandbits(16) for _ in range(3)] == leak:
            print("recovered seed:", hex(guess))
            break


if __name__ == "__main__":
    main()
