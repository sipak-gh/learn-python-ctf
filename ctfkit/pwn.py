"""Pwn helpers: cyclic offsets, flat payload building, and leak math.

Binary exploitation with Python is mostly bookkeeping: find the offset to the
saved return address, pack addresses correctly, and turn one leaked address
into every other address you need. These helpers do that arithmetic; pwntools
provides the heavy machinery (``ELF``, ``ROP``, ``process``, ``remote``).
"""
from __future__ import annotations

import struct

__all__ = [
    "p64",
    "u64",
    "p32",
    "u32",
    "cyclic",
    "cyclic_find",
    "flat",
    "libc_base",
    "resolve",
]

# de Bruijn alphabet matching pwntools' default, so cyclic_find agrees with it.
_ALPHABET = b"abcdefghijklmnopqrstuvwxyz"


def p64(value: int) -> bytes:
    """Pack an int as little-endian unsigned 64-bit."""
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def u64(data: bytes) -> int:
    """Unpack little-endian unsigned 64-bit, right-padding short leaks with NULs."""
    return struct.unpack("<Q", data.ljust(8, b"\x00")[:8])[0]


def p32(value: int) -> bytes:
    """Pack an int as little-endian unsigned 32-bit."""
    return struct.pack("<I", value & 0xFFFFFFFF)


def u32(data: bytes) -> int:
    """Unpack little-endian unsigned 32-bit, right-padding short leaks with NULs."""
    return struct.unpack("<I", data.ljust(4, b"\x00")[:4])[0]


def _de_bruijn(alphabet: bytes, n: int):
    """Generate a de Bruijn sequence over ``alphabet`` with subsequence length ``n``."""
    k = len(alphabet)
    a = [0] * k * n
    seq = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                seq.extend(a[1 : p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return (alphabet[i] for i in seq)


def cyclic(length: int, n: int = 4) -> bytes:
    """A de Bruijn pattern of ``length`` bytes (every ``n``-byte window unique).

    Send this as the overflow; whatever ``n`` bytes land in the saved return
    address are unique, so :func:`cyclic_find` tells you the exact offset.
    """
    gen = _de_bruijn(_ALPHABET, n)
    out = bytearray()
    for _ in range(length):
        try:
            out.append(next(gen))
        except StopIteration:
            raise ValueError("pattern exhausted; increase n")
    return bytes(out)


def cyclic_find(sub: bytes | int, n: int = 4) -> int:
    """Return the offset of ``sub`` within :func:`cyclic` (the overflow offset).

    ``sub`` is the value that landed in the return address -- pass the raw
    bytes or an int (it is packed little-endian, matching what you read off
    the stack).
    """
    if isinstance(sub, int):
        sub = sub.to_bytes(n, "little").rstrip(b"\x00") or b"\x00"
    pattern = cyclic(len(_ALPHABET) ** n if len(sub) >= n else 10000, n)
    idx = pattern.find(sub)
    if idx == -1:
        raise ValueError(f"{sub!r} not found in cyclic pattern")
    return idx


def flat(*parts, filler: bytes = b"A", length: int | None = None) -> bytes:
    """Concatenate ints (packed p64) and bytes into one payload.

    Ints become little-endian 64-bit; bytes/str pass through. With ``length``
    the result is padded with ``filler`` to a fixed size -- handy for
    "overflow this exact buffer then overwrite saved RIP".
    """
    out = bytearray()
    for part in parts:
        if isinstance(part, int):
            out += p64(part)
        elif isinstance(part, str):
            out += part.encode()
        else:
            out += bytes(part)
    if length is not None:
        if len(out) > length:
            raise ValueError(f"payload {len(out)} exceeds length {length}")
        out += filler * (length - len(out))
    return bytes(out)


def libc_base(leak: int, symbol_offset: int) -> int:
    """Compute the libc load base from one leaked address.

    ``leak`` is a runtime address of a known symbol; ``symbol_offset`` is that
    symbol's offset in the libc file (from ``ELF.symbols``). ASLR shifts the
    whole library by a constant, so ``base = leak - offset``.
    """
    base = leak - symbol_offset
    if base & 0xFFF:
        raise ValueError(
            f"base {base:#x} is not page-aligned; wrong symbol offset or bad leak?"
        )
    return base


def resolve(base: int, offset: int) -> int:
    """Turn a (recovered) base plus a file offset into a runtime address."""
    return base + offset
