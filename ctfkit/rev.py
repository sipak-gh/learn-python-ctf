"""Reversing helpers: read ``.pyc`` files, marshalled code, and bytecode.

Python compiles to bytecode stored in ``.pyc`` files under ``__pycache__``.
The format is a small header followed by a ``marshal``-serialised code
object. If a challenge leaks a ``.pyc`` you can often skip decompilation
entirely and read the constants and disassembly directly.
"""
from __future__ import annotations

import dis
import importlib.util
import io
import marshal
import struct
from types import CodeType

__all__ = [
    "PYC_MAGIC_3_10",
    "pyc_header_len",
    "load_pyc",
    "load_marshal",
    "disassemble",
    "walk_consts",
    "find_strings",
]

# CPython 3.10's bytecode magic (little-endian u16 + b"\r\n"). The magic ties
# a .pyc to one interpreter version -- a 3.10 .pyc only loads under 3.10.
PYC_MAGIC_3_10 = importlib.util.MAGIC_NUMBER


def pyc_header_len(data: bytes) -> int:
    """Return the header length for a ``.pyc`` (16 bytes since 3.7's PEP 552)."""
    # bytes 4..8 are a bit field; bit 0 set means a 16-byte hash-based header.
    (flags,) = struct.unpack_from("<I", data, 4)
    return 16


def load_marshal(data: bytes) -> CodeType:
    """Unmarshal a raw code-object blob (no ``.pyc`` header)."""
    return marshal.loads(data)


def load_pyc(data: bytes) -> CodeType:
    """Parse a ``.pyc``: skip the header, unmarshal the code object.

    Raises a clear error if the magic does not match the running interpreter,
    because that is the usual reason a leaked ``.pyc`` "won't load".
    """
    magic = data[:4]
    if magic != PYC_MAGIC_3_10:
        raise ValueError(
            f"magic {magic.hex()} != this interpreter's {PYC_MAGIC_3_10.hex()}; "
            "run under the matching Python version"
        )
    return marshal.loads(data[pyc_header_len(data):])


def disassemble(code: CodeType | bytes | object) -> str:
    """Return the ``dis`` disassembly of a code object as a string."""
    buf = io.StringIO()
    dis.dis(code, file=buf)
    return buf.getvalue()


def walk_consts(code: CodeType):
    """Yield every constant in ``code`` and nested code objects, recursively."""
    for const in code.co_consts:
        yield const
        if isinstance(const, CodeType):
            yield from walk_consts(const)


def find_strings(code: CodeType) -> list[str]:
    """Collect all string constants (including nested functions).

    Reading the string table of a leaked code object is often enough to lift
    a hardcoded secret without running anything.
    """
    out = []
    for const in walk_consts(code):
        if isinstance(const, str):
            out.append(const)
        elif isinstance(const, bytes):
            try:
                out.append(const.decode("latin-1"))
            except Exception:
                pass
    return out
