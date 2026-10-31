"""Crypto helpers: XOR breaking, RSA machinery and attacks, PRNG recovery.

Grown across three chapters:

* ch04 -- :func:`single_byte_xor`, :func:`break_single_byte_xor`,
  :func:`guess_keysize`, :func:`break_repeating_key_xor`.
* ch05 -- :func:`rsa_decrypt`, :func:`factor_fermat`, :func:`cube_root`,
  :func:`rsa_attack_small_e`, :func:`rsa_attack_prime_modulus`.
* ch06 -- :class:`MT19937` (untemper 624 outputs, predict forward),
  :class:`LFSR`.

Each attack is keyed to the *clue* that reveals it (small ``e``, a prime
modulus, a leaked key, 624 leaked outputs). The maths is written out so you
can see the structure, not just import a black box.
"""
from __future__ import annotations

import math
from typing import Iterable, Sequence

from .encoding import long_to_bytes, printable_ratio, to_bytes, xor

__all__ = [
    "single_byte_xor",
    "break_single_byte_xor",
    "hamming",
    "guess_keysize",
    "break_repeating_key_xor",
    "egcd",
    "modinv",
    "cube_root",
    "iroot",
    "rsa_decrypt",
    "factor_fermat",
    "rsa_attack_prime_modulus",
    "rsa_attack_small_e",
]

# ---------------------------------------------------------------------------
# ch04 -- XOR
# ---------------------------------------------------------------------------

# Letters, space and common punctuation dominate English text; weight them so
# a candidate plaintext full of them scores highly.
_ENGLISH = b"ETAOIN SHRDLUetaoin shrdlu"


def single_byte_xor(data: bytes, key: int) -> bytes:
    """XOR every byte of ``data`` with the single byte ``key``."""
    return bytes(b ^ key for b in data)


def _english_score(data: bytes) -> float:
    """Crude printable-English score (higher is better)."""
    if not data:
        return 0.0
    freq = sum(data.count(c) for c in _ENGLISH)
    return printable_ratio(data) * 2 + freq / len(data)


def break_single_byte_xor(data: bytes) -> tuple[int, bytes, float]:
    """Brute all 256 keys; return ``(key, plaintext, score)`` for the best.

    The clue for this attack is a ciphertext that is a fixed length with no
    structure -- a single-byte key only has 256 possibilities, so you just
    try them all and rank by "looks like English".
    """
    best = (0, b"", -1.0)
    for key in range(256):
        candidate = single_byte_xor(data, key)
        score = _english_score(candidate)
        if score > best[2]:
            best = (key, candidate, score)
    return best


def hamming(a: bytes, b: bytes) -> int:
    """Bitwise Hamming distance between two equal-length byte strings."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_keysize(data: bytes, lo: int = 2, hi: int = 40, top: int = 3) -> list[int]:
    """Rank likely repeating-XOR key sizes by normalised Hamming distance.

    The right key size makes neighbouring blocks line up, so their Hamming
    distance per bit is smallest. Returns the ``top`` best candidates.
    """
    scores = []
    hi = min(hi, len(data) // 2)
    for size in range(lo, hi + 1):
        blocks = [data[i * size : (i + 1) * size] for i in range(4)]
        pairs = [(blocks[i], blocks[j]) for i in range(4) for j in range(i + 1, 4)]
        dist = sum(hamming(x, y) for x, y in pairs) / (len(pairs) * size)
        scores.append((dist, size))
    scores.sort()
    return [size for _, size in scores[:top]]


def break_repeating_key_xor(data: bytes, keysize: int | None = None) -> tuple[bytes, bytes]:
    """Recover a repeating XOR key by solving each key position independently.

    Transpose the ciphertext into ``keysize`` columns; each column is a
    single-byte XOR, so :func:`break_single_byte_xor` cracks it. Returns
    ``(key, plaintext)``.
    """
    if keysize is None:
        keysize = guess_keysize(data)[0]
    key = bytearray()
    for i in range(keysize):
        column = data[i::keysize]
        k, _, _ = break_single_byte_xor(column)
        key.append(k)
    return bytes(key), xor(data, bytes(key))


# ---------------------------------------------------------------------------
# ch05 -- RSA
# ---------------------------------------------------------------------------


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclid: return ``(g, x, y)`` with ``a*x + b*y == g``."""
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a: int, m: int) -> int:
    """Modular inverse of ``a`` mod ``m`` (raises if none exists)."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m}")
    return x % m


def iroot(n: int, k: int) -> tuple[int, bool]:
    """Integer ``k``-th root of ``n``: ``(root, exact)`` via binary search."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return (0, True)
    lo, hi = 1, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**k <= n:
            lo = mid
        else:
            hi = mid - 1
    return (lo, lo**k == n)


def cube_root(n: int) -> tuple[int, bool]:
    """Integer cube root; ``(root, exact)``. The ``e=3`` no-padding attack."""
    return iroot(n, 3)


def rsa_decrypt(c: int, d: int, n: int) -> bytes:
    """Textbook RSA decrypt ``c`` with private exponent ``d``: ``m = c^d mod n``.

    Use when the clue is "you were handed the private key" -- no attack, just
    apply the maths.
    """
    return long_to_bytes(pow(c, d, n))


def factor_fermat(n: int, max_steps: int = 1_000_000) -> tuple[int, int]:
    """Fermat factorisation: fast when ``p`` and ``q`` are close in size.

    The clue is a modulus whose factors are "balanced" (e.g. two halves of a
    flag). Writes ``n = a^2 - b^2 = (a-b)(a+b)``.
    """
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return (a - b, a + b)
        a += 1
    raise ValueError("Fermat factorisation did not converge")


def rsa_attack_prime_modulus(c: int, e: int, n: int) -> bytes:
    """When ``n`` is prime, ``phi = n - 1`` directly -- no factoring needed.

    Clue: the "modulus" is actually prime (a single large prime, not a
    semiprime). Then ``d = e^{-1} mod (n-1)``.
    """
    d = modinv(e, n - 1)
    return rsa_decrypt(c, d, n)


def rsa_attack_small_e(c: int, e: int, n: int | None = None) -> bytes:
    """Small ``e`` with no padding: if ``m^e < n`` then ``m`` is a plain root.

    Clue: ``e`` is tiny (often 3) and the message is short, so the modular
    reduction never happens and ``c`` is a perfect ``e``-th power.
    """
    root, exact = iroot(c, e)
    if exact:
        return long_to_bytes(root)
    # Otherwise m^e = c + k*n for some small k; try adding multiples of n.
    if n is not None:
        k = 1
        while k < 1_000_000:
            root, exact = iroot(c + k * n, e)
            if exact:
                return long_to_bytes(root)
            k += 1
    raise ValueError("no exact e-th root found; message may be padded or e too large")


