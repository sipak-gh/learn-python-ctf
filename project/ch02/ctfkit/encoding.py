"""Encoding helpers: the byte-wrangling you do in every challenge.

CTF data arrives as hex, base64, URL-escapes, ROT-rotated text, or XOR'd
bytes. These helpers are thin wrappers over the standard library so the
*intent* is obvious at the call site. Each one takes and returns ``bytes``
unless noted, because on the wire everything is bytes.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import string
import urllib.parse

__all__ = [
    "to_bytes",
    "xor",
    "hexdump",
    "from_hex",
    "to_hex",
    "b64d",
    "b64e",
    "url_decode",
    "url_encode",
    "rot",
    "rot13",
    "bytes_to_long",
    "long_to_bytes",
    "printable_ratio",
]


def to_bytes(data: bytes | bytearray | str, encoding: str = "utf-8") -> bytes:
    """Coerce ``str``/``bytearray``/``bytes`` to ``bytes``.

    Lets the other helpers accept a literal string without the caller
    sprinkling ``.encode()`` everywhere.
    """
    if isinstance(data, str):
        return data.encode(encoding)
    return bytes(data)


def xor(a: bytes | str, b: bytes | str) -> bytes:
    """XOR two byte strings, cycling the shorter one (usually the key).

    XOR is the workhorse of CTF crypto: it is its own inverse, so the same
    call both encrypts and decrypts.
    """
    a = to_bytes(a)
    b = to_bytes(b)
    if not b:
        raise ValueError("second operand must be non-empty")
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))


def to_hex(data: bytes | str) -> str:
    """Bytes -> lowercase hex string."""
    return to_bytes(data).hex()


def from_hex(text: str) -> bytes:
    """Hex string -> bytes. Ignores whitespace so you can paste a dump."""
    return bytes.fromhex("".join(text.split()))


def b64e(data: bytes | str) -> bytes:
    """Standard base64 encode, returning bytes."""
    return base64.b64encode(to_bytes(data))


def b64d(data: bytes | str, urlsafe: bool = False) -> bytes:
    """Base64 decode, tolerating missing ``=`` padding.

    Challenges often strip padding; we add it back so the decode does not
    raise :class:`binascii.Error`.
    """
    raw = to_bytes(data)
    raw += b"=" * (-len(raw) % 4)
    if urlsafe:
        return base64.urlsafe_b64decode(raw)
    return base64.b64decode(raw)


def url_encode(data: bytes | str, safe: str = "") -> str:
    """Percent-encode every unsafe byte (``safe`` keeps characters literal)."""
    return urllib.parse.quote(to_bytes(data), safe=safe)


def url_decode(text: str) -> bytes:
    """Percent-decode to raw bytes."""
    return urllib.parse.unquote_to_bytes(text)


def rot(text: str, n: int = 13) -> str:
    """Caesar-rotate ASCII letters by ``n`` (digits and symbols untouched)."""
    n %= 26
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    table = str.maketrans(
        lower + upper,
        lower[n:] + lower[:n] + upper[n:] + upper[:n],
    )
    return text.translate(table)


def rot13(text: str) -> str:
    """ROT13, the self-inverse special case of :func:`rot`."""
    return codecs.encode(text, "rot13")


def bytes_to_long(data: bytes | str) -> int:
    """Big-endian bytes -> integer (``int.from_bytes`` with a CTF-friendly name)."""
    return int.from_bytes(to_bytes(data), "big")


def long_to_bytes(n: int) -> bytes:
    """Integer -> big-endian bytes, the inverse of :func:`bytes_to_long`."""
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII.

    A quick score for "does this look like text?" -- handy when brute-forcing
    keys and ranking candidate plaintexts.
    """
    if not data:
        return 0.0
    good = sum(1 for byte in data if 0x20 <= byte < 0x7F or byte in (9, 10, 13))
    return good / len(data)


def hexdump(data: bytes, width: int = 16) -> str:
    """A ``hexdump -C`` style view, for eyeballing binary blobs."""
    data = to_bytes(data)
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asciipart = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(lines)
