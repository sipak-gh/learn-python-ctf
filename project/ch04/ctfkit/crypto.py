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


