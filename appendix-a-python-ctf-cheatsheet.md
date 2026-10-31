# Appendix A — Python-for-CTF Cheat Sheet

The one-liners you reach for in every challenge: bytes ↔ ints ↔ text, packing binary, modular arithmetic,
brute-force loops, and shelling out. Everything here is plain standard library — no `ctfkit`, no
third-party packages — so it works in any Python 3.10+ shell.

Each block is runnable as-is: paste it into `python3`, and the **Output** block under it is the real
result. For the `ctfkit` wrappers see [Appendix C](appendix-c-ctfkit-reference.md); for pwntools
equivalents see [Appendix B](appendix-b-pwntools-reference.md).

## Bytes and str

On the wire everything is `bytes`. `str` is text. Keep them apart; convert at the edges.

```python
s = "DUCTF"
b = s.encode()                       # str -> bytes (UTF-8)
print(b, type(b).__name__)
print(b.decode())                    # bytes -> str
print(bytes([68, 85, 67, 84, 70]))   # from a list of ints
print(list(b))                       # bytes -> list[int]
print(b[0], chr(b[0]), ord("D"))     # indexing bytes gives an int
print(b"abc" + b"def", b"ab" * 3)    # concatenate / repeat
```

```text
b'DUCTF' bytes
DUCTF
b'DUCTF'
[68, 85, 67, 84, 70]
68 D 68
b'abcdef' b'ababab'
```

Gotchas:

- Indexing `bytes` yields an `int` (`b"A"[0]` is `65`); slicing yields `bytes` (`b"A"[0:1]` is `b"A"`).
- `.decode()` raises `UnicodeDecodeError` on non-UTF-8 data. For "just give me characters" use
  `.decode("latin-1")`, which maps every byte 0–255 one-to-one.

## Hex

```python
print(b"\xde\xad\xbe\xef".hex())     # bytes -> hex string
print(bytes.fromhex("deadbeef"))     # hex string -> bytes
print(b"\xde\xad".hex(" "))          # 3.8+ separator for readability
print(hex(1337), int("0x539", 16), int("539", 16))
print(format(255, "02x"), f"{255:#x}")   # zero-pad / 0x prefix
```

```text
deadbeef
b'\xde\xad\xbe\xef'
de ad
0x539 1337 1337
ff 0xff
```

`bytes.fromhex` ignores inner spaces but not newlines; strip a pasted dump first
(`bytes.fromhex("".join(text.split()))`).

## Base64, base32, base16

```python
import base64, binascii
print(base64.b64encode(b"flag{x}"))
print(base64.b64decode("ZmxhZ3t4fQ=="))
print(base64.urlsafe_b64encode(b"\xfb\xff"))   # - and _ instead of + and /
print(base64.b16decode("DEADBEEF"))            # base16 == hex (uppercase)
print(base64.b32encode(b"hi"))
print(binascii.hexlify(b"hi"), binascii.unhexlify(b"6869"))
```

```text
b'ZmxhZ3t4fQ=='
b'flag{x}'
b'-_8='
b'\xde\xad\xbe\xef'
b'NBUQ===='
b'6869' b'hi'
```

Missing `=` padding makes `b64decode` raise `binascii.Error`. Add it back:
`data += b"=" * (-len(data) % 4)` (this is what [`ctfkit.encoding.b64d`](appendix-c-ctfkit-reference.md)
does for you).

## Int ↔ bytes and modular exponentiation

Crypto treats a byte string as one big-endian integer. These two conversions are the backbone of the
RSA chapter ([Chapter 5](05-rsa.md)).

```python
n = int.from_bytes(b"flag", "big")
print(n)
print(n.to_bytes(4, "big"))
print(n.to_bytes((n.bit_length() + 7) // 8, "big"))   # minimal width
print(int.from_bytes(b"\x01\x00", "little"))
print(pow(2, 10, 1000))          # (2**10) % 1000, but never builds the huge power
print(pow(17, -1, 3120))         # modular inverse (Python 3.8+)
print(pow(42, 65537, 3233))      # textbook RSA encrypt: m^e mod n
```

```text
1718378855
b'flag'
b'flag'
1
24
2753
2557
```

`pow(a, -1, m)` raises `ValueError` when `a` and `m` are not coprime — that itself is a clue (a shared
factor you can `math.gcd` out).

## struct — packing binary

`struct` converts between Python values and C structs. Format chars: `<`/`>` endianness, `B`/`H`/`I`/`Q`
= unsigned 8/16/32/64-bit, `s` = raw bytes.

```python
import struct
print(struct.pack("<I", 0x41424344))      # little-endian u32
print(struct.pack(">I", 0x41424344))      # big-endian u32
print(struct.unpack("<Q", b"\x01\x00\x00\x00\x00\x00\x00\x00"))
print(struct.pack("<4sH", b"PK\x03\x04"[:4], 20))
print(struct.calcsize("<IHB"))
a, b = struct.unpack("<HH", b"\xff\xff\x00\x01")
print(a, b)
```

```text
b'DCBA'
b'ABCD'
(1,)
b'PK\x03\x04\x14\x00'
7
65535 256
```

`unpack` always returns a tuple, even for one value. For address packing in pwn use
[`ctfkit.pwn.p64`/`u64`](appendix-c-ctfkit-reference.md) or pwntools' `p64`/`u64`.

## itertools — brute force without nested loops

```python
import itertools, string
print(["".join(p) for p in itertools.product("01", repeat=2)])
print(list(itertools.permutations("ABC", 2))[:3])
print(list(itertools.combinations(range(4), 2)))
for cand in itertools.product(string.ascii_lowercase, repeat=3):   # brute a 3-char pin
    if "".join(cand) == "cat":
        print("found", "".join(cand)); break
print(list(itertools.islice(itertools.cycle("AB"), 5)))   # repeat forever, take 5
print(list(itertools.islice(itertools.count(10, 2), 4)))  # 10,12,14,...
```

```text
['00', '01', '10', '11']
[('A', 'B'), ('A', 'C'), ('B', 'A')]
[(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]
found cat
['A', 'B', 'A', 'B', 'A']
[10, 12, 14, 16]
```

`product(alphabet, repeat=n)` is the keyspace of an `n`-character key — the standard brute-force loop.
`cycle` is how a repeating-key XOR extends a short key over a long message.

## subprocess — run another program

```python
import subprocess
out = subprocess.run(["echo", "hello"], capture_output=True, text=True)
print(repr(out.stdout), out.returncode)
print(subprocess.check_output(["printf", "%s-%s", "a", "b"]).decode())
p = subprocess.run(["rev"], input="abc\n", capture_output=True, text=True)  # feed stdin
print(p.stdout.strip())
```

```text
'hello\n' 0
a-b
cba
```

Pass a list of arguments (not a shell string) so there's no shell to inject into. Use `shell=True` only
when you truly need shell features, never with untrusted input.

## ROT13, codecs, and URL encoding

```python
import codecs, urllib.parse
print(codecs.encode("Uryyb", "rot13"))          # ROT13 (letters only)
print(codecs.decode("68656c6c6f", "hex"))        # hex codec
print(urllib.parse.quote("a b/c?"))              # percent-encode
print(urllib.parse.unquote_to_bytes("%de%ad%be%ef"))   # -> raw bytes
print("Hello".translate(str.maketrans("lo", "LO")))    # cheap substitution cipher
```

```text
Hello
b'hello'
a%20b/c%3F
b'\xde\xad\xbe\xef'
HeLLO
```

`str.maketrans` + `str.translate` is the fastest way to apply a substitution alphabet — handy for
Caesar/ROT-`n` and the Unicode-homoglyph tricks in [Chapter 2](02-python-for-ctf-data.md).

## XOR by hand

XOR is its own inverse, so one expression both encrypts and decrypts.

```python
a = b"\x10\x20\x30"
print(bytes(x ^ 0x55 for x in a))                       # single-byte key
key = b"KEY"
ct = bytes(x ^ key[i % len(key)] for i, x in enumerate(b"attack"))   # repeating key
print(ct.hex())
print(bytes(x ^ key[i % len(key)] for i, x in enumerate(ct)))        # same code decrypts
```

```text
b'Eue'
2a312d2a2632
b'attack'
```

[`ctfkit.encoding.xor`](appendix-c-ctfkit-reference.md) is exactly this loop with the key-cycling
built in. XOR breaking (brute single-byte, recover repeating keys) is [Chapter 4](04-classical-and-xor.md).

## Hashing and character classes

```python
import hashlib, string
print(hashlib.md5(b"abc").hexdigest())
print(hashlib.sha256(b"abc").hexdigest()[:16], "...")
print(string.printable[:20])
print(string.ascii_lowercase, string.digits)
```

```text
900150983cd24fb0d6963f7d28e17f72
ba7816bf8f01cfea ...
0123456789abcdefghij
abcdefghijklmnopqrstuvwxyz 0123456789
```

`string.printable`, `string.ascii_lowercase`, and `string.digits` are ready-made brute-force
alphabets. `hashlib` covers the usual proof-of-work and integrity checks you meet at a service prompt.

## One-liner reference

| Task | Expression |
|------|-----------|
| str → bytes | `s.encode()` |
| bytes → str | `b.decode()` (or `b.decode("latin-1")` for raw) |
| bytes → hex | `b.hex()` |
| hex → bytes | `bytes.fromhex(h)` |
| bytes → int (big-endian) | `int.from_bytes(b, "big")` |
| int → bytes | `n.to_bytes((n.bit_length()+7)//8, "big")` |
| base64 decode (pad-safe) | `base64.b64decode(s + "=" * (-len(s) % 4))` |
| modular inverse | `pow(a, -1, m)` |
| RSA decrypt | `pow(c, d, n)` |
| pack LE u64 | `struct.pack("<Q", x)` |
| brute n-char key | `itertools.product(alphabet, repeat=n)` |
| single-byte XOR | `bytes(x ^ k for x in data)` |
| run a program, capture output | `subprocess.run(cmd, capture_output=True).stdout` |

## See also

- [Appendix B — pwntools Quick Reference](appendix-b-pwntools-reference.md) for `p64`/`u64`, tubes, and ELF math.
- [Appendix C — `ctfkit` API Reference](appendix-c-ctfkit-reference.md) for the course's wrappers over these idioms.
- [Chapter 2 — Python for CTF: Bytes, Numbers, and Encodings](02-python-for-ctf-data.md) teaches these from scratch.

Sources for this appendix: [REFERENCES.md](REFERENCES.md#appendix-a--python-for-ctf-cheat-sheet)
