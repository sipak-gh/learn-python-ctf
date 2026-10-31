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
    "untemper",
    "MT19937",
    "LFSR",
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


# ---------------------------------------------------------------------------
# ch06 -- PRNG recovery
# ---------------------------------------------------------------------------

_MT_N = 624
_MT_LOWER = 0x7FFFFFFF
_MT_UPPER = 0x80000000


_MT_MASK32 = 0xFFFFFFFF


def _undo_rshift_xor(y: int, shift: int, mask: int = _MT_MASK32) -> int:
    """Invert ``y = x ^ ((x >> shift) & mask)``, reconstructing from the top."""
    x = 0
    for i in range(32):
        bit = 31 - i
        src = bit + shift
        known = (x >> src) & 1 if src < 32 else 0
        xbit = ((y >> bit) & 1) ^ (known & ((mask >> bit) & 1))
        x |= xbit << bit
    return x & _MT_MASK32


def _undo_lshift_xor(y: int, shift: int, mask: int) -> int:
    """Invert ``y = x ^ ((x << shift) & mask)``, reconstructing from the bottom."""
    x = 0
    for bit in range(32):
        src = bit - shift
        known = (x >> src) & 1 if src >= 0 else 0
        xbit = ((y >> bit) & 1) ^ (known & ((mask >> bit) & 1))
        x |= xbit << bit
    return x & _MT_MASK32


def untemper(y: int) -> int:
    """Invert MT19937's output tempering to recover one internal state word.

    MT19937 hides each state word behind four reversible shift/xor/mask
    steps. Inverting all four (in reverse order) turns a leaked 32-bit output
    back into the state word that produced it. Collect 624 of these and you
    have the whole generator state.
    """
    y = _undo_rshift_xor(y, 18)                 # undo y ^= y >> 18
    y = _undo_lshift_xor(y, 15, 0xEFC60000)     # undo y ^= (y << 15) & 0xEFC60000
    y = _undo_lshift_xor(y, 7, 0x9D2C5680)      # undo y ^= (y << 7)  & 0x9D2C5680
    y = _undo_rshift_xor(y, 11)                 # undo y ^= y >> 11
    return y & _MT_MASK32


class MT19937:
    """A pure-Python MT19937 you can seed *with recovered state*.

    This is the untempering attack that replaces SageMath for
    ``encrypted-mail``: feed it 624 consecutive 32-bit outputs of a target
    ``random`` (via :meth:`from_outputs`) and it predicts every future value.
    """

    def __init__(self, state: Sequence[int] | None = None, index: int = _MT_N):
        self.mt = list(state) if state is not None else [0] * _MT_N
        self.index = index

    @classmethod
    def from_outputs(cls, outputs: Iterable[int]) -> "MT19937":
        """Build a generator from 624 tempered 32-bit outputs."""
        state = [untemper(y) for y in outputs]
        if len(state) != _MT_N:
            raise ValueError(f"need exactly {_MT_N} outputs, got {len(state)}")
        # index=624 forces a twist on the first call, matching a real MT that
        # has just emitted its 624th output.
        return cls(state, index=_MT_N)

    @classmethod
    def from_seed(cls, seed: int) -> "MT19937":
        """Seed exactly like CPython's ``random.seed(int)`` init_by_array."""
        mt = [0] * _MT_N
        mt[0] = 19650218
        for i in range(1, _MT_N):
            mt[i] = (1812433253 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xFFFFFFFF
        key = cls._seed_to_key(seed)
        i, j = 1, 0
        for _ in range(max(_MT_N, len(key))):
            mt[i] = ((mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1664525)) + key[j] + j) & 0xFFFFFFFF
            i += 1
            j += 1
            if i >= _MT_N:
                mt[0] = mt[_MT_N - 1]
                i = 1
            if j >= len(key):
                j = 0
        for _ in range(_MT_N - 1):
            mt[i] = ((mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1566083941)) - i) & 0xFFFFFFFF
            i += 1
            if i >= _MT_N:
                mt[0] = mt[_MT_N - 1]
                i = 1
        mt[0] = 0x80000000
        return cls(mt, index=_MT_N)

    @staticmethod
    def _seed_to_key(seed: int) -> list[int]:
        if seed == 0:
            return [0]
        key = []
        while seed:
            key.append(seed & 0xFFFFFFFF)
            seed >>= 32
        return key

    def _twist(self) -> None:
        for i in range(_MT_N):
            y = (self.mt[i] & _MT_UPPER) + (self.mt[(i + 1) % _MT_N] & _MT_LOWER)
            self.mt[i] = self.mt[(i + 397) % _MT_N] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= 0x9908B0DF
        self.index = 0

    def next_u32(self) -> int:
        """Return the next 32-bit output, applying tempering."""
        if self.index >= _MT_N:
            self._twist()
        y = self.mt[self.index]
        self.index += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF

    def random(self) -> float:
        """Reproduce CPython ``random.random()``: 53-bit float in [0, 1)."""
        a = self.next_u32() >> 5
        b = self.next_u32() >> 6
        return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0)


class LFSR:
    """A Galois/Fibonacci-style LFSR with recoverable state over GF(2).

    Used in ch06 for linear generators whose future output you predict after
    watching enough bits. A linear generator leaks: if you can see as many
    output bits as the register is wide, you can solve for its taps/state.
    """

    def __init__(self, state: list[int], taps: Sequence[int]):
        self.state = list(state)
        self.taps = list(taps)

    def clock(self) -> int:
        """Advance one step; return the output bit (the shifted-out LSB)."""
        out = self.state[-1]
        feedback = 0
        for t in self.taps:
            feedback ^= self.state[t]
        self.state = [feedback] + self.state[:-1]
        return out

    def bits(self, n: int) -> list[int]:
        """Return the next ``n`` output bits."""
        return [self.clock() for _ in range(n)]

    @staticmethod
    def recover_state(outputs: Sequence[int], taps: Sequence[int], width: int) -> list[int]:
        """Recover the initial register state from observed output bits.

        :meth:`clock` shifts the register's last bit out and a feedback bit in,
        so the first ``width`` outputs are the initial contents in shift-out
        order -- the reverse of the register. Reversing them reconstructs the
        starting state, which loaded back into an :class:`LFSR` with the same
        ``taps`` reproduces the stream. Independent of the tap positions.
        """
        if len(outputs) < width:
            raise ValueError(f"need at least {width} output bits")
        return list(outputs[:width])[::-1]
