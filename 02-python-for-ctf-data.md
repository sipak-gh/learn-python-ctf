# Chapter 2 — Python for CTF: Bytes, Numbers, and Encodings

Challenge data is rarely plain text. It arrives as hex, base64, URL-escapes, a big integer, or raw
binary. This chapter teaches the Python conversions you'll use in *every* later chapter, builds the first
`ctfkit` module (`encoding`), and solves two DownUnderCTF encoding puzzles. Previous:
[Chapter 1](01-getting-started.md). Next: [Chapter 3](03-talking-to-services.md).

## bytes vs str

This distinction trips up every Python newcomer doing CTF. Get it straight once and the rest is easy.

- **`str`** is *text*: a sequence of Unicode code points — use it for actual words.
- **`bytes`** is *raw data*: a sequence of integers 0–255. Files, sockets, and crypto are all `bytes`.

You convert between them explicitly:

- `str.encode(enc)` → `bytes` (default `enc` is `"utf-8"`).
- `bytes.decode(enc)` → `str`.

`examples/ch02/str_bytes.py`

```python
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
```

```console
$ python examples/ch02/str_bytes.py
text: 'flag' str
raw: b'flag' bytes
back to str: 'flag'
raw[0] = 102 (an int)
raw[0:1] = b'f' (bytes)
blob: b'\x89PNG\r\n' len 6
latin-1: 'ÿþabc'
replace: '��abc'
```

Two gotchas to burn in:

- **Indexing `bytes` gives an `int`, not one-byte `bytes`.** `raw[0]` is `102`; `raw[0:1]` is `b'f'`.
- **`decode()` raises on invalid UTF-8.** To just see bytes as characters, decode with
  `"latin-1"` (every byte 0–255 maps to one character) or pass `errors="replace"`.

> **Design idea:** keep everything as `bytes` on the wire and in crypto, and only `decode()` at the edge
> when you know it's text. Mixing the two is the #1 source of `TypeError: a bytes-like object is required`.

## Hex and base64

Both turn raw bytes into an ASCII-safe string so binary survives a text channel. You decode them
constantly.

- **Hex** — two characters per byte. `bytes.hex()` and `bytes.fromhex()` are the idiomatic pair;
  `fromhex` ignores whitespace so you can paste a dump.
- **Base64** — four characters per three bytes (~33% larger). `base64.b64encode` / `b64decode`.

`examples/ch02/hex_base64.py`

```python
import base64
import binascii

raw = b"\xde\xad\xbe\xef"

# Hex: bytes.hex() and bytes.fromhex() are the idiomatic pair.
h = raw.hex()
print("hex:", h)
print("round-trip:", bytes.fromhex(h) == raw)

# fromhex ignores spaces, so you can paste a dump straight in.
print("spaced:", bytes.fromhex("de ad be ef"))

# binascii does the same with a different name (you'll see both in writeups).
print("binascii:", binascii.hexlify(raw).decode())

# Base64: standard and url-safe alphabets.
msg = b"clue>hypothesis>flag"
enc = base64.b64encode(msg)
print("b64:", enc.decode())
print("b64 decode:", base64.b64decode(enc))

# CTF data often drops the '=' padding; restore it before decoding.
unpadded = "aGVsbG8"          # "hello" without padding
padded = unpadded + "=" * (-len(unpadded) % 4)
print("repadded:", base64.b64decode(padded))
```

```console
$ python examples/ch02/hex_base64.py
hex: deadbeef
round-trip: True
spaced: b'\xde\xad\xbe\xef'
binascii: deadbeef
b64: Y2x1ZT5oeXBvdGhlc2lzPmZsYWc=
b64 decode: b'clue>hypothesis>flag'
repadded: b'hello'
```

> **Gotcha:** base64's length must be a multiple of 4, padded with `=`. Challenges love to strip the
> padding, so `base64.b64decode` raises `binascii.Error: Invalid base64-encoded string`. Fix it with the
> one-liner above: `data + "=" * (-len(data) % 4)`.

## Integers and bytes, and `pow`

Crypto treats a message as one big number. Python's `int` is unbounded, so a 256-byte RSA block is just an
integer you can multiply and exponentiate.

- `int.from_bytes(b, "big")` reads bytes as a base-256 number (most-significant byte first).
- `n.to_bytes(length, "big")` writes it back — you must supply a `length` big enough to hold `n`.
- `pow(base, exp, mod)` is fast modular exponentiation, computed in `O(log exp)` without ever building the
  huge intermediate. It's the single most important function in RSA ([Chapter 5](05-rsa.md)).
- `pow(a, -1, m)` (Python 3.8+) is the modular inverse of `a` mod `m`.

`examples/ch02/int_bytes.py`

```python
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
```

```console
$ python examples/ch02/int_bytes.py
as int: 4923915796838313597
as bytes: b'DUCTF{n}'
empty -> 0
pow(7, 1234567, 100003) = 50681
inverse of 3 mod 100003: 66669
```

`"big"` (big-endian) is the convention for crypto: the first byte is the most significant, so a message and
its integer compare the same way. Watch the byte order — `struct` and some formats use little-endian.

## XOR

XOR is the workhorse of CTF crypto because it's **its own inverse**: `p ^ k ^ k == p` — the same operation
encrypts and decrypts. A key shorter than the data is **cycled** (repeating-key XOR). You break XOR by
hand in [Chapter 4](04-classical-and-xor.md); here's the primitive.

`examples/ch02/xor_demo.py`

```python
from ctfkit.encoding import xor

# By hand: zip the data with a cycled key.
def xor_by_hand(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

plain = b"attack at dawn"
key = b"KEY"
ct = xor_by_hand(plain, key)
print("cipher hex:", ct.hex())
print("decrypt   :", xor_by_hand(ct, key))

# ctfkit.encoding.xor does exactly this, and accepts str or bytes.
print("ctfkit xor:", xor(ct, key))
print("self-inverse:", xor(xor(plain, key), key) == plain)

# Single-byte key: the classic "XOR cipher" you brute-force in ch04.
one = xor(b"secret", b"\x2a")
print("single-byte:", one.hex(), "->", xor(one, b"\x2a"))
```

```console
$ python examples/ch02/xor_demo.py
cipher hex: 2a312d2a26326b242d6b21383c2b
decrypt   : b'attack at dawn'
ctfkit xor: b'attack at dawn'
self-inverse: True
single-byte: 594f49584f5e -> b'secret'
```

## ROT and URL encoding

Two more encodings you'll meet in the easy tiers:

- **ROT13 / Caesar** rotate letters by a fixed amount. ROT13 is self-inverse; any other shift needs the
  opposite shift to undo. Digits and symbols are untouched.
- **URL / percent-encoding** escapes unsafe bytes as `%XX` so they survive a URL or form field.

`examples/ch02/rot_url.py`

```python
import codecs
import urllib.parse

from ctfkit.encoding import rot, rot13, url_encode, url_decode

# ROT13 via the stdlib codec, and via ctfkit (same result).
print("codecs rot13:", codecs.encode("Hello", "rot13"))
print("ctfkit rot13:", rot13("Hello"))
print("twice       :", rot13(rot13("Hello")))

# Any shift; ctfkit.rot leaves digits and symbols alone.
print("shift 3:", rot("abcXYZ 123", 3))

# Percent-encoding. A space, a brace, and a non-ASCII byte all get escaped.
s = "flag={a b}"
enc = url_encode(s)
print("url_encode:", enc)
print("url_decode:", url_decode(enc))

# The stdlib equivalents you'll see in writeups.
print("quote     :", urllib.parse.quote(s, safe=""))
```

```console
$ python examples/ch02/rot_url.py
codecs rot13: Uryyb
ctfkit rot13: Uryyb
twice       : Hello
shift 3: defABC 123
url_encode: flag%3D%7Ba%20b%7D
url_decode: b'flag={a b}'
quote     : flag%3D%7Ba%20b%7D
```

## struct: fixed-width binary fields

File formats and binary protocols are structs of fixed-width integers. `struct` converts between Python
ints and their byte layout. The format string sets byte order and field sizes:

- `<` little-endian, `>` big-endian (network order).
- `B` uint8, `H` uint16, `I` uint32, `Q` uint64.

`examples/ch02/struct_demo.py`

```python
import struct

# Pack three fields into a little-endian header.
header = struct.pack("<IHB", 0xDEADBEEF, 0x1234, 7)
print("packed:", header.hex())

# Unpack them back. unpack always returns a tuple.
magic, ver, flags = struct.unpack("<IHB", header)
print(f"magic={magic:#x} ver={ver:#x} flags={flags}")

# Byte order matters: same bytes, different endianness.
print("LE:", struct.unpack("<I", b"\x01\x00\x00\x00")[0])
print("BE:", struct.unpack(">I", b"\x01\x00\x00\x00")[0])

# A PNG's width/height live as two big-endian uint32 at offset 16.
png_ihdr = bytes.fromhex("0000010000000080")  # width=256, height=128
width, height = struct.unpack(">II", png_ihdr)
print("png size:", width, "x", height)
```

```console
$ python examples/ch02/struct_demo.py
packed: efbeadde341207
magic=0xdeadbeef ver=0x1234 flags=7
LE: 1
BE: 16777216
png size: 256 x 128
```

The f-string specs matter: `{magic:#x}` prints hex with a `0x` prefix, and `{off:08x}` (in the hexdump
helper below) zero-pads to 8 hex digits — you'll use these to print offsets and addresses.

## Building ctfkit: `ctfkit.encoding`

The first real module. `ctfkit.encoding` wraps the conversions above in thin, intention-named helpers, so
solve scripts read by meaning instead of a pile of `.encode()` / `base64` / `int.from_bytes` noise. Every
helper takes and returns `bytes` unless noted — on the wire everything is bytes.

Create `ctfkit/encoding.py`. The header and the `to_bytes`/`xor` core:

```python
"""Encoding helpers: the byte-wrangling you do in every challenge."""
from __future__ import annotations

import base64
import binascii
import codecs
import string
import urllib.parse

__all__ = [
    "to_bytes", "xor", "hexdump", "from_hex", "to_hex", "b64d", "b64e",
    "url_decode", "url_encode", "rot", "rot13",
    "bytes_to_long", "long_to_bytes", "printable_ratio",
]


def to_bytes(data: bytes | bytearray | str, encoding: str = "utf-8") -> bytes:
    """Coerce str/bytearray/bytes to bytes, so callers can pass a literal str."""
    if isinstance(data, str):
        return data.encode(encoding)
    return bytes(data)


def xor(a: bytes | str, b: bytes | str) -> bytes:
    """XOR two byte strings, cycling the shorter one (usually the key)."""
    a = to_bytes(a)
    b = to_bytes(b)
    if not b:
        raise ValueError("second operand must be non-empty")
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))
```

The hex / base64 / url helpers, all tolerant of sloppy input:

```python
def to_hex(data: bytes | str) -> str:
    return to_bytes(data).hex()


def from_hex(text: str) -> bytes:
    """Hex string -> bytes. Ignores whitespace so you can paste a dump."""
    return bytes.fromhex("".join(text.split()))


def b64e(data: bytes | str) -> bytes:
    return base64.b64encode(to_bytes(data))


def b64d(data: bytes | str, urlsafe: bool = False) -> bytes:
    """Base64 decode, tolerating missing '=' padding."""
    raw = to_bytes(data)
    raw += b"=" * (-len(raw) % 4)
    if urlsafe:
        return base64.urlsafe_b64decode(raw)
    return base64.b64decode(raw)


def url_encode(data: bytes | str, safe: str = "") -> str:
    return urllib.parse.quote(to_bytes(data), safe=safe)


def url_decode(text: str) -> bytes:
    return urllib.parse.unquote_to_bytes(text)
```

The ROT and int/bytes helpers, plus two scoring/eyeball utilities:

```python
def rot(text: str, n: int = 13) -> str:
    """Caesar-rotate ASCII letters by n (digits and symbols untouched)."""
    n %= 26
    lower, upper = string.ascii_lowercase, string.ascii_uppercase
    table = str.maketrans(
        lower + upper,
        lower[n:] + lower[:n] + upper[n:] + upper[:n],
    )
    return text.translate(table)


def rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def bytes_to_long(data: bytes | str) -> int:
    return int.from_bytes(to_bytes(data), "big")


def long_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII -- a 'does this look like text?' score."""
    if not data:
        return 0.0
    good = sum(1 for b in data if 0x20 <= b < 0x7F or b in (9, 10, 13))
    return good / len(data)


def hexdump(data: bytes, width: int = 16) -> str:
    """A `hexdump -C` style view, for eyeballing binary blobs."""
    data = to_bytes(data)
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asciipart = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(lines)
```

`printable_ratio` scores a candidate plaintext — how you'll rank 256 XOR guesses in
[Chapter 4](04-classical-and-xor.md). `hexdump` is for eyeballing a blob of unknown shape.

### Checkpoint

Add `tests/test_encoding.py`:

```python
from ctfkit import encoding as e


def test_xor_roundtrip_and_cycle():
    key = b"KEY"
    ct = e.xor(b"hello world", key)
    assert e.xor(ct, key) == b"hello world"
    assert e.xor(b"\x00\x00\x00\x00", b"\x01\x02") == b"\x01\x02\x01\x02"


def test_hex_and_base64_tolerate_sloppy_input():
    assert e.from_hex("de ad\nbe ef") == bytes.fromhex("deadbeef")
    assert e.b64d("aGVsbG8") == b"hello"          # missing padding restored
    assert e.b64e(b"hello") == b"aGVsbG8="


def test_rot_and_rot13():
    assert e.rot("abcXYZ", 1) == "bcdYZA"
    assert e.rot13("Hello") == "Uryyb"
    assert e.rot13(e.rot13("Hello")) == "Hello"


def test_long_bytes_roundtrip():
    for n in (1, 255, 256, 65535, 1 << 200):
        assert e.bytes_to_long(e.long_to_bytes(n)) == n


def test_printable_ratio():
    assert e.printable_ratio(b"hello") == 1.0
    assert e.printable_ratio(b"\x00\x01\x02\x03") == 0.0
```

```console
$ pytest -q
.....                                                                    [100%]
5 passed in 0.01s
```

The complete project at this point is in `project/ch02/`.

## Challenge walkthrough: welcome-to-ductf

> **Challenge:** `welcome-to-ductf` — DownUnderCTF 2023 by \_pix\_. Source:
> `DownUnderCTF/Challenges_2023_Public`@`b48f83db29` (`beginner/welcome-to-ductf`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py welcome-to-ductf
$ ls challenges/welcome-to-ductf/src
upside-down.a++  welcome-to-ductf.aplusplus
$ file challenges/welcome-to-ductf/src/upside-down.a++
challenges/welcome-to-ductf/src/upside-down.a++: Unicode text, UTF-8 text
```

The prompt is written **upside down**, with a hint to "Try reading bottom up!":

```text
¡ƃɐlɟ ǝɥʇ ʇno noʎ ʇuᴉɹd ll,ʇᴉ puɐ ɹǝʇǝɹdɹǝʇuᴉ ǝɥʇ ɥƃnoɹɥʇ ʇᴉ unɹ puɐ ǝɹǝɥ ǝpoɔ sᴉɥʇ ǝʞɐʇ ʇsnJ
...Yo'uve heard of C++ but can I introduce you to the better, faster, more profanity inclusive Aussie PluS PluS.
```

### Clues

> **Clue:** the text is **upside down and mirrored**, built from Unicode homoglyphs (`ƃɐlɟ`, `H∀Ǝ⅄`). That
> means two reversible transforms: reverse the order of lines and characters, then map each flipped glyph
> back to its ASCII letter.

> **Clue:** the hints name the language — "Aussie++" (aussieplusplus). The flag doesn't require *running*
> the esolang; the source builds it by plain string concatenation, visible once flipped.

### Test the hypothesis

Flip the file and read it. The author's public flip-table (normal ↔ flipped glyph pairs) undoes the glyph
swap; reversing line and character order undoes the upside-down layout. The result is readable Aussie++:

```text
I RECKON GLAF = "DUCTF{";
...
    I RECKON HappyHouR = "1ts-5oCl0cK_5om3wh3RE";
...
	GIMME GLAF + HappyHouR + STREWTH;
```

A **dead end to avoid:** there's a decoy assignment earlier —
`I RECKON YA_FLAG = "CTFDU{YaFlagAin'tHeReMate!}";` — inside a `PRINT_FLAG` function that's never the final
output. The real flag is the last `GIMME` (Aussie++ for "return/print"): it concatenates `GLAF`,
`HappyHouR`, and `STREWTH`. Resolve those three variables.

### Solve

The solve builds the flip table, flips the text, scrapes every `I RECKON <name> = "<value>"` assignment
into a dict, then obeys the final `GIMME a + b + c` to join them.

`examples/ch02/solve_welcome_to_ductf.py`

```python
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "welcome-to-ductf", "src", "upside-down.a++")

# The author's flip table (pairs of normal<->flipped glyphs).
_FLIPS = ['?', '¿', "'", ',', ',', "'", '[', ']', ']', '[', '!', '¡', 'a', 'ɐ',
          'b', 'q', 'c', 'ɔ', 'd', 'p', 'e', 'ǝ', 'f', 'ɟ', 'g', 'ƃ', 'h', 'ɥ',
          # ... full table in the committed script ...
          '"', '„']
FLIPS = {_FLIPS[i]: _FLIPS[i + 1] for i in range(0, len(_FLIPS), 2)}
FLIPS |= {_FLIPS[i + 1]: _FLIPS[i] for i in range(0, len(_FLIPS), 2)}


def flip(text: str) -> str:
    lines = text.splitlines()
    chars = list("\n".join(line[::-1] for line in lines[::-1]))
    return "".join(FLIPS.get(c, c) for c in chars)


def main() -> None:
    upside_down = open(CHALL, encoding="utf-8").read()
    source = flip(upside_down)
    print("flipped source:\n" + source + "\n")

    # Collect every `I RECKON <name> = "<value>";` assignment...
    env = dict(re.findall(r'I RECKON (\S+) = "([^"]*)"', source))
    # ...then obey the final concatenation `GIMME A + B + C;`.
    gimme = re.search(r"GIMME\s+(\S+ \+ \S+ \+ \S+);", source)
    names = [n.strip() for n in gimme.group(1).split("+")]
    flag = "".join(env[n] for n in names)
    print("FLAG:", flag)


if __name__ == "__main__":
    main()
```

```console
$ python examples/ch02/solve_welcome_to_ductf.py
flipped source:
G'DAY MATE!

IMPOHT ME FUNC HitTheSacK;
I RECKON STREWTH = "}";
IMPOHT ME FUNC ChucKSomeDice;

THE HARD YAKKA FOR PRINT_FLAG IS () <
  GIMME "YEAH MATE!, LETS PRINT THE FLAG";
  HitTheSacK(5000);

  I RECKON ME_BBQ = 1;
  I RECKON YA_FLAG = "CTFDU{YaFlagAin'tHeReMate!}";

  YA RECKON ME_BBQ == 1 ? <
    GIMME YA_FLAG;
  >

  HitTheSacK(5000);
>


I RECKON GLAF = "DUCTF{";
THE HARD YAKKA FOR THE_CTF IS () <
	GIMME "Fetch'n the flag foR ya mate!";
    I RECKON HappyHouR = "1ts-5oCl0cK_5om3wh3RE";
	I RECKON I'LL HAVE A WALKABOUT UNTIL (YEAH, NAH!) <
	    GIMME "WheRe the flamin' galah is ya flag...";

		HitTheSacK(1000);

		YA RECKON ChucKSomeDice(0, 6) == 0 ? MATE FUCK THIS;
	>
  GIMME "Bloody hell mate, I found it, some Right Bloody dRongo left it neaR a cRoc";
	GIMME GLAF + HappyHouR + STREWTH;
>

THE_CTF();

GIMME "Enjoy the Rest of the CTF!";

CHEERS C***!

FLAG: DUCTF{1ts-5oCl0cK_5om3wh3RE}
```

### Why it worked / generalize

This is **homoglyph / visual obfuscation**: text dressed up in confusable Unicode and a reversed layout.
Both tricks are reversible — undo them with a lookup table and a reverse. The decoy flag is a reminder to
read *what the program actually outputs*, not the first flag-shaped string you see. The instinct:
**when a file is "Unicode text" but unreadable, suspect a glyph substitution and look for a mapping
table.**

## Challenge walkthrough: complementary

> **Challenge:** `complementary` — DownUnderCTF 2023 by joseph. Source:
> `DownUnderCTF/Challenges_2023_Public`@`b48f83db29` (`beginner/complementary`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py complementary
$ ls challenges/complementary/src
complementary.py  flag.txt  output.txt
```

The whole program is four lines:

```python
flag = open('./flag.txt', 'rb').read().strip()
m1 = int.from_bytes(flag[:len(flag)//2])
m2 = int.from_bytes(flag[len(flag)//2:])
n = m1 * m2
print(n)
```

`output.txt` holds one big integer `n`.

### Clues

> **Clue:** the flag is split in half, each half becomes an integer via `int.from_bytes`, and the only
> output is their **product** `n = m1 * m2`. There's no modulus and no exponent — despite the "crypto"
> vibe, it's a plain multiplication.

> **Clue (prompt):** *"Two halves make a whole."* The two integers are the two flag halves. Recovering them
> means **factoring** `n`.

### Test the hypothesis

Your first instinct (from [Chapter 5](05-rsa.md)) might be Fermat's method — fast when the two factors are
close in size. But a 37-byte flag splits into 18- and 19-byte halves, so the factors differ in size and
Fermat won't converge. The dead end teaches the real shape: the halves are ASCII text, so each is a
*composite* with small prime factors. Fully factor `n` with `sympy.factorint`, then partition those primes
into two groups until both decode to printable bytes forming `DUCTF{...}`.

### Solve

`examples/ch02/solve_complementary.py`

```python
import itertools
import os
from functools import reduce

import sympy

from ctfkit.encoding import long_to_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTPUT = os.path.join(REPO, "challenges", "complementary", "src", "output.txt")


def main() -> None:
    n = int(open(OUTPUT).read().strip())
    factor_counts = sympy.factorint(n)
    primes = []
    for prime, exp in factor_counts.items():
        primes += [prime] * exp
    print(f"n has {len(primes)} prime factors; searching splits...")

    seen = set()
    for r in range(1, len(primes)):
        for combo in itertools.combinations(range(len(primes)), r):
            m1 = reduce(lambda a, i: a * primes[i], combo, 1)
            if m1 in seen:
                continue
            seen.add(m1)
            m2 = n // m1
            flag = long_to_bytes(m1) + long_to_bytes(m2)
            if flag.startswith(b"DUCTF{") and flag.endswith(b"}") and flag.isascii():
                print("FLAG:", flag.decode())
                return
    raise SystemExit("no printable split found")


if __name__ == "__main__":
    main()
```

```console
$ python examples/ch02/solve_complementary.py
n has 10 prime factors; searching splits...
FLAG: DUCTF{is_1nt3ger_f4ct0r1s4t10n_h4rd?}
```

### Why it worked / generalize

The challenge dressed up `int↔bytes` plus factoring as "crypto." The clue was the *absence* of real
cryptography — no modulus, no exponent — leaving a factoring problem. Because the secret was ASCII, `n` was
a smooth composite that `factorint` cracks instantly; the only work left was the right split of its prime
factors. This bridges into RSA ([Chapter 5](05-rsa.md)), where factoring `n` *is* the attack — just harder
when the factors are two big primes.

## Summary

- **`bytes` is data, `str` is text.** Convert with `.encode()` / `.decode()`; indexing bytes gives an
  `int`, slicing gives `bytes`.
- Hex (`.hex()` / `.fromhex()`) and base64 (`b64encode` / `b64decode`) make binary text-safe; restore
  stripped base64 padding with `data + "=" * (-len(data) % 4)`.
- A message is a big integer: `int.from_bytes(b, "big")` / `n.to_bytes(len, "big")`, and `pow(c, d, n)` /
  `pow(a, -1, m)` for modular math.
- XOR is self-inverse and cycles its key; ROT13/Caesar and URL-encoding round out the easy encodings;
  `struct` reads fixed-width binary fields.
- `ctfkit.encoding` wraps all of this so solve scripts read by intent.
- Two solves showed encodings *as the whole challenge*: homoglyph flip (`welcome-to-ductf`) and
  int↔bytes + factoring (`complementary`).

## Exercises

1. **Chained encodings.** This blob is the hex of a base64 string. Peel both layers:
   `61 47 56 73 62 47 38 3d`.

   <details><summary>Solution</summary>

   Work outside-in: undo the hex to get the base64 text, then base64-decode it.

   ```python
   from ctfkit.encoding import from_hex, b64d
   print(from_hex("61 47 56 73 62 47 38 3d"))   # b'aGVsbG8='  (the base64 layer)
   print(b64d(from_hex("61 47 56 73 62 47 38 3d")))   # b'hello'
   ```

   The habit to build: **verify each layer prints something sane before decoding the next.** You can build
   your own test blob with `to_hex(b64e(b"hello"))`.
   </details>

2. **int ↔ bytes.** Turn `DUCTF{halves}` into an integer, split it as the challenge does (first half, second
   half as two ints), multiply, then recover both halves by factoring.

   <details><summary>Solution</summary>

   ```python
   import sympy
   from ctfkit.encoding import bytes_to_long, long_to_bytes
   flag = b"DUCTF{halves}"
   m1 = bytes_to_long(flag[:len(flag)//2])
   m2 = bytes_to_long(flag[len(flag)//2:])
   n = m1 * m2
   # m1, m2 are recoverable by the same factor-and-split search as the solve.
   print(long_to_bytes(m1) + long_to_bytes(m2))   # b'DUCTF{halves}'
   ```
   </details>

3. **Printable scoring.** Single-byte XOR a flag, then recover it. Because many keys yield *printable*
   output (XOR with `0x20` just swaps letter case), `printable_ratio` only *narrows* the field — you pick
   the flag-shaped candidate. Recover the key for `bytes.fromhex("1d1f021e191e17")`.

   <details><summary>Solution</summary>

   ```python
   from ctfkit.encoding import xor, printable_ratio
   ct = bytes.fromhex("1d1f021e191e17")
   for k in range(256):
       guess = xor(ct, bytes([k]))
       if printable_ratio(guess) == 1.0:
           print(hex(k), guess)
   # 0x70 b'morning'  -- among the printable candidates, this is the real word
   ```

   Several keys print cleanly; only one reads as English. Ranking by *English-ness* instead of mere
   printability is exactly what single-byte XOR breaking adds in [Chapter 4](04-classical-and-xor.md).
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-2--python-for-ctf-bytes-numbers-and-encodings)
