#!/usr/bin/env python3
"""bytes vs str -- the distinction that trips up every Python newcomer in CTF.

* ``str`` is text (a sequence of Unicode code points).
* ``bytes`` is raw data (a sequence of integers 0-255).
Data on the wire, in files, and in crypto is always ``bytes``. You convert
with ``.encode()`` (str -> bytes) and ``.decode()`` (bytes -> str).
"""

text = "flag"          # str
raw = text.encode()    # bytes, default UTF-8
print("text:", repr(text), type(text).__name__)
print("raw:", repr(raw), type(raw).__name__)
print("back to str:", repr(raw.decode()))

# Indexing bytes gives an int; slicing gives bytes.
print("raw[0] =", raw[0], "(an int)")
print("raw[0:1] =", repr(raw[0:1]), "(bytes)")

# A bytes literal takes \xNN escapes; non-ASCII bytes have no str equivalent.
blob = b"\x89PNG\r\n"
print("blob:", repr(blob), "len", len(blob))

# decode() raises on invalid UTF-8; use errors= or latin-1 to force it.
mixed = b"\xff\xfeabc"
print("latin-1:", repr(mixed.decode("latin-1")))
print("replace:", repr(mixed.decode("utf-8", "replace")))
