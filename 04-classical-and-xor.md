# Chapter 4 — Classical Ciphers and XOR

Crypto challenges start where cryptography started: shuffle the alphabet, add a repeating key, and
hope nobody notices the structure. They always notice. This chapter covers the classical ciphers
(Caesar, substitution, Vigenère), the frequency analysis and crib dragging that break them, then the
operation behind almost every modern CTF crypto task — **XOR**. You'll break single-byte XOR by brute
force, repeating-key XOR by key-length detection, and any keyed stream by crib dragging. Then you grow
`ctfkit.crypto` with XOR tools and solve two LA CTF challenges.

Builds on [Chapter 2](02-python-for-ctf-data.md) (bytes, hex, `xor`); leads into [Chapter 5](05-rsa.md),
where the maths gets heavier.

## The design idea behind classical ciphers

Every classical cipher hides a message by **relabelling or shifting symbols with a key**. None hide
*structure*. English is full of structure — letter frequencies, word shapes, a flag prefix — and it
survives the cipher. The game: find structure the cipher didn't destroy, and pull on it.

| Cipher | Key | What it preserves (your lever) |
|--------|-----|--------------------------------|
| Caesar | one shift (0–25) | letter frequencies; only 26 keys |
| Substitution | a full alphabet permutation | letter/word frequencies |
| Vigenère | a repeating word | per-column frequencies once you know the key length |
| XOR (repeating key) | a repeating byte string | the same, byte-for-byte |

### Caesar: 26 keys is not a keyspace

A Caesar cipher shifts each letter by a fixed amount. With 26 possibilities you never "attack" it — you
print every rotation and read the English one. `ctfkit.encoding.rot` (from Chapter 2) does one shift.

`examples/ch04/caesar.py`

```python
from ctfkit.encoding import rot

CIPHERTEXT = "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"  # shifted by 3


def brute(text: str):
    for n in range(26):
        yield n, rot(text, n)


def main() -> None:
    for n, candidate in brute(CIPHERTEXT):
        print(f"{n:2d}: {candidate}")
```

```console
$ python examples/ch04/caesar.py
 0: Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj
 1: Xli uymgo fvsar jsb nyqtw sziv xli pedc hsk
...
23: The quick brown fox jumps over the lazy dog
...
25: Vjg swkem dtqyp hqz lworu qxgt vjg ncba fqi
```

Shift 23 (`-3`) is the plaintext. Reading 26 lines is fine for one line; the next section automates the
choice.

### Frequency analysis: let the letters vote

For a longer substitution you don't want to eyeball every option. Score each candidate by how close its
letter distribution is to English using the **chi-squared** statistic — the lowest score wins.

`examples/ch04/frequency.py`

```python
from ctfkit.encoding import rot

ENGLISH = {  # relative frequency (%) of each letter in English
    "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2, "g": 2.0,
    "h": 6.1, "i": 7.0, "j": 0.15, "k": 0.77, "l": 4.0, "m": 2.4, "n": 6.7,
    "o": 7.5, "p": 1.9, "q": 0.095, "r": 6.0, "s": 6.3, "t": 9.1, "u": 2.8,
    "v": 0.98, "w": 2.4, "x": 0.15, "y": 2.0, "z": 0.074,
}

CIPHERTEXT = "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"


def chi_squared(text: str) -> float:
    letters = [c for c in text.lower() if c.isalpha()]
    n = len(letters)
    score = 0.0
    for ch, pct in ENGLISH.items():
        expected = pct / 100 * n
        observed = letters.count(ch)
        if expected:
            score += (observed - expected) ** 2 / expected
    return score


def main() -> None:
    best = min(range(26), key=lambda k: chi_squared(rot(CIPHERTEXT, k)))
    print(f"best shift = {best}")
    print(f"plaintext  = {rot(CIPHERTEXT, best)}")
```

```console
$ python examples/ch04/frequency.py
best shift = 23
plaintext  = The quick brown fox jumps over the lazy dog
```

The same scoring powers `break_single_byte_xor` below — "which key makes the most English" is a question
you ask constantly in crypto.

### Vigenère: a repeating key is many Caesars

Vigenère shifts letter *i* by key letter *i*, with the key repeating. It resisted hand analysis for
centuries, but the weakness is simple: **if you know the key length, every key position is
a plain Caesar.** That "split into columns, solve each independently" trick is exactly how you break
repeating-key XOR later — only the alphabet changes.

`examples/ch04/vigenere.py`

```python
def shift(text: str, key: str, sign: int) -> str:
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k = ord(key[ki % len(key)].lower()) - ord("a")
            out.append(chr((ord(ch) - base + sign * k) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def encrypt(text, key): return shift(text, key, +1)
def decrypt(text, key): return shift(text, key, -1)


def main() -> None:
    pt, key = "attack at dawn", "LEMON"
    ct = encrypt(pt, key)
    print("ciphertext:", ct)
    print("decrypted :", decrypt(ct, key))
```

```console
$ python examples/ch04/vigenere.py
ciphertext: lxfopv ef rnhr
decrypted : attack at dawn
```

## XOR: the one operation you must own

Most CTF crypto that isn't RSA is XOR in some disguise. Three properties make it the workhorse:

- **Self-inverse:** `a ^ k ^ k == a`. Encryption and decryption are the *same* function.
- **Identity/annihilation:** `a ^ 0 == a` and `a ^ a == 0`.
- **Key cancels on reuse:** `(p1 ^ k) ^ (p2 ^ k) == p1 ^ p2`. If a key is reused, XORing two
  ciphertexts removes the key entirely and leaks the XOR of the plaintexts.

In Python, `^` XORs two `int`s; to XOR byte strings you zip them. `ctfkit.encoding.xor` (Chapter 2)
cycles the shorter operand, so it doubles as repeating-key XOR.

`examples/ch04/xor_basics.py`

```python
from ctfkit.encoding import xor


def main() -> None:
    a, k = 0x6C, 0x5A
    print(f"single byte:  {a:#04x} ^ {k:#04x} = {a ^ k:#04x}, back = {a ^ k ^ k:#04x}")

    msg, key = b"flag{xor_is_reversible}", b"\x13"
    enc = xor(msg, key)              # key cycles over the message
    print("encrypted :", enc.hex())
    print("decrypted :", xor(enc, key))

    # Key reuse: two messages under the same key leak their XOR.
    p1, p2, k2 = b"attack at dawn!!", b"defend till noon", b"SECRETKEYSECRETK"
    leak = xor(xor(p1, k2), xor(p2, k2))
    print("p1 ^ p2   :", leak)
    print("via direct:", xor(p1, p2))
```

```console
$ python examples/ch04/xor_basics.py
single byte:  0x6c ^ 0x5a = 0x36, back = 0x6c
encrypted : 757f7274686b7c614c7a604c6176657661607a717f766e
decrypted : b'flag{xor_is_reversible}'
p1 ^ p2   : b'\x05\x11\x12\x04\r\x0f\x00\x15\x1dL\x08A\x19\x01NO'
via direct: b'\x05\x11\x12\x04\r\x0f\x00\x15\x1dL\x08A\x19\x01NO'
```

> **Python idiom.** `bytes(b ^ key for b in data)` XORs every byte with a single key byte. A `bytes`
> object yields `int`s when you iterate it, so no conversion is needed — this is the body of
> `single_byte_xor`.

### Single-byte XOR: brute all 256 keys

A single-byte key has 256 possibilities. Decrypt with each, score for English, keep the best — the Caesar
frequency attack over bytes. This is the first `ctfkit.crypto` function.

`examples/ch04/single_byte_break.py`

```python
from ctfkit.crypto import break_single_byte_xor, single_byte_xor

# "Cooking MC's like a pound of bacon" XORed with one byte (the classic example).
CIPHERTEXT = bytes.fromhex(
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
)


def main() -> None:
    key, plaintext, score = break_single_byte_xor(CIPHERTEXT)
    print(f"key  = {key:#04x} ({key!r})")
    print(f"text = {plaintext.decode()}")
    print(f"score= {score:.3f}")
    assert single_byte_xor(plaintext, key) == CIPHERTEXT
    print("round-trip OK")
```

```console
$ python examples/ch04/single_byte_break.py
key  = 0x58 (88)
text = Cooking MC's like a pound of bacon
score= 2.853
round-trip OK
```

### Repeating-key XOR: find the length, then split columns

A repeating byte key cycles over the message. Two steps break it:

1. **Guess the key length.** The right length makes repeated blocks line up, so their bitwise
   **Hamming distance** (per byte) is smallest. `guess_keysize` ranks candidates this way.
2. **Split into columns.** Byte positions `i, i+keysize, i+2*keysize, …` all used the same key byte, so
   each column is a single-byte XOR. Break each column, concatenate the key bytes.

`examples/ch04/repeating_xor.py`

```python
from ctfkit.crypto import break_repeating_key_xor, guess_keysize
from ctfkit.encoding import xor

PLAINTEXT = (
    b"The clue-driven method turns a pile of files into a flag: recon, then "
    b"clues, then a hypothesis you actually test. Repeating-key XOR falls to "
    b"frequency analysis one column at a time, which is why practitioners reach "
    b"for a stream cipher or a real KDF instead of a short cycled key."
)
KEY = b"CTFKIT"


def main() -> None:
    ct = xor(PLAINTEXT, KEY)
    print("keysize candidates:", guess_keysize(ct))
    found_key, recovered = break_repeating_key_xor(ct)
    print("recovered key     :", found_key)
    print("plaintext starts  :", recovered[:48].decode())
    print("exact match       :", recovered == PLAINTEXT)
```

```console
$ python examples/ch04/repeating_xor.py
keysize candidates: [6, 5, 18]
recovered key     : b'CTFKIT'
plaintext starts  : The clue-driven method turns a pile of files int
exact match       : True
```

The true key length (6) comes out on top. This is the classic Kasiski/Hamming attack from cryptopals; it
needs enough ciphertext — a few bytes won't have enough repeated blocks for the distance to stand out.

### Crib dragging: when you know a word

Often you don't need to guess a length. If you know a piece of plaintext in a XOR
ciphertext — a flag prefix like `lactf{`, an HTTP header, a known quote — XOR the crib against the
ciphertext at that position and the **exact key bytes** fall out. Drag a long enough crib and you have
the whole key.

`examples/ch04/crib_drag.py`

```python
from ctfkit.encoding import xor

KEY = b"S3cr3tKey!!"
FLAG = b"lactf{crib_dragging_peels_the_key_right_off}"
CIPHERTEXT = xor(FLAG, KEY)          # repeating-key XOR


def drag(ciphertext: bytes, crib: bytes, offset: int) -> bytes:
    """Key bytes revealed by placing `crib` at `offset`."""
    return xor(ciphertext[offset:offset + len(crib)], crib)


def main() -> None:
    revealed = drag(CIPHERTEXT, b"lactf{", 0)
    print("key bytes from crib:", revealed)       # == KEY[:6]
    key = xor(CIPHERTEXT[:len(KEY)], FLAG[:len(KEY)])
    print("full key           :", key)
    print("recovered plaintext:", xor(CIPHERTEXT, key).decode())
```

```console
$ python examples/ch04/crib_drag.py
key bytes from crib: b'S3cr3t'
full key           : b'S3cr3tKey!!'
recovered plaintext: lactf{crib_dragging_peels_the_key_right_off}
```

Crib dragging is the most useful XOR skill in CTFs. Both challenges below are crib drags in different
costumes.

## Building ctfkit: `ctfkit.crypto` (XOR)

This chapter creates `ctfkit/crypto.py`. It grows over the next two chapters (RSA in Chapter 5,
PRNG recovery in Chapter 6); for now it holds the XOR toolkit. Add it alongside `encoding.py` and
`io.py`.

The module reuses helpers from `ctfkit.encoding`: `xor`, `printable_ratio`, `long_to_bytes`, `to_bytes`.

`project/ch04/ctfkit/crypto.py` (the XOR half)

```python
from .encoding import long_to_bytes, printable_ratio, to_bytes, xor

__all__ = [
    "single_byte_xor", "break_single_byte_xor",
    "hamming", "guess_keysize", "break_repeating_key_xor",
]

# Letters, space and common punctuation dominate English; weight them.
_ENGLISH = b"ETAOIN SHRDLUetaoin shrdlu"


def single_byte_xor(data: bytes, key: int) -> bytes:
    """XOR every byte of `data` with the single byte `key`."""
    return bytes(b ^ key for b in data)


def _english_score(data: bytes) -> float:
    if not data:
        return 0.0
    freq = sum(data.count(c) for c in _ENGLISH)
    return printable_ratio(data) * 2 + freq / len(data)


def break_single_byte_xor(data: bytes) -> tuple[int, bytes, float]:
    """Brute all 256 keys; return (key, plaintext, score) for the best."""
    best = (0, b"", -1.0)
    for key in range(256):
        candidate = single_byte_xor(data, key)
        score = _english_score(candidate)
        if score > best[2]:
            best = (key, candidate, score)
    return best
```

The repeating-key half detects the key length with normalised Hamming distance, then solves each column
as a single-byte XOR:

```python
def hamming(a: bytes, b: bytes) -> int:
    """Bitwise Hamming distance between two equal-length byte strings."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_keysize(data: bytes, lo: int = 2, hi: int = 40, top: int = 3) -> list[int]:
    """Rank likely key sizes by normalised Hamming distance (smallest first)."""
    scores = []
    hi = min(hi, len(data) // 2)
    for size in range(lo, hi + 1):
        blocks = [data[i * size:(i + 1) * size] for i in range(4)]
        pairs = [(blocks[i], blocks[j]) for i in range(4) for j in range(i + 1, 4)]
        dist = sum(hamming(x, y) for x, y in pairs) / (len(pairs) * size)
        scores.append((dist, size))
    scores.sort()
    return [size for _, size in scores[:top]]


def break_repeating_key_xor(data, keysize=None) -> tuple[bytes, bytes]:
    """Recover a repeating XOR key by solving each key position independently."""
    if keysize is None:
        keysize = guess_keysize(data)[0]
    key = bytearray()
    for i in range(keysize):
        k, _, _ = break_single_byte_xor(data[i::keysize])
        key.append(k)
    return bytes(key), xor(data, bytes(key))
```

> **Gotcha.** `guess_keysize` compares four blocks, so it needs `len(data) >= 8 * keysize` to be
> reliable. On short ciphertexts the distances are noisy and the real length may not come first — pass
> `keysize=` explicitly when you already know it (as the test does).

Add the matching tests in `tests/test_crypto.py`:

```python
from ctfkit import crypto as c
from ctfkit.encoding import xor


def test_single_byte_xor_break():
    pt = b"The quick brown fox jumps over the lazy dog and runs away."
    ct = c.single_byte_xor(pt, 0x5A)
    key, recovered, _ = c.break_single_byte_xor(ct)
    assert key == 0x5A and recovered == pt


def test_repeating_key_xor_break():
    pt = (b"When in the course of human events it becomes necessary for one "
          b"people to dissolve the political bands which have connected them.")
    ct = xor(pt, b"ICE")
    found_key, recovered = c.break_repeating_key_xor(ct, keysize=3)
    assert found_key == b"ICE" and recovered == pt
```

### Checkpoint

```console
$ cd project/ch04 && python -m pytest -q
........                                                                 [100%]
8 passed in 0.02s
```

Eight tests pass (five `encoding` tests and one `io` test from earlier chapters, plus these two).
The complete project at this point is in `project/ch04/`.

## Challenge walkthrough: greek-cipher

> Challenge: **greek-cipher** — LA CTF 2023 by ACM Cyber at UCLA.
> Source: `uclaacm/lactf-archive@3379d4a7b3` (`2023/crypto/greek-cipher`).
> License: MIT (© 2024 ACM at UCLA).

### Recon

```console
$ python challenges/fetch.py greek-cipher
$ ls challenges/greek-cipher
challenge.yaml  greek.txt
$ file challenges/greek-cipher/greek.txt
greek.txt: Unicode text, UTF-8 text, with very long lines (344), with no line terminators
$ head -c 60 challenges/greek-cipher/greek.txt
κςκ ωπν αζπλ ιησι χνοςνθ μσγθσρ ...
```

One file of Greek-looking UTF-8 text, laid out like English prose: spaces between words, punctuation,
one `{...}` token. No script, no key.

### Clues

> **Clue:** The text has word boundaries and English sentence rhythm, but every letter is a Greek
> glyph. That is a **monoalphabetic substitution** — one cipher symbol always maps to one plaintext
> letter. Frequencies and word shapes are preserved.

> **Clue:** There is exactly one token containing `{`. In an LA CTF challenge the flag is `lactf{...}`,
> so that token *is* the flag — a built-in crib.

> **Clue:** The prose reads like an intro sentence. Guessing an opening like "did you know that julius
> caesar…" pins a dozen letters at once. Combined, these cribs recover the whole map.

Clue → hypothesis: align guessed plaintext words to the cipher words position-by-position, build the
`cipher glyph → plain letter` map, apply it everywhere, and read the flag. This is solving an
"aristocrat" puzzle, just scripted.

### Test the hypothesis

Confirm it's a one-to-one substitution before writing a solver: count distinct glyphs and check
word-length patterns match English. The first cipher word is three glyphs, like "did"; the repeated
long phrases match "did you know that julius caesar". Each glyph is multi-byte UTF-8, but Python
iterates strings by *character*, not byte — so you map glyph-to-letter directly without touching the
encoding.

### Solve

`examples/ch04/solve_greek_cipher.py`

```python
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "greek-cipher", "greek.txt")

# Our guessed plaintext, used only to learn the mapping. Need not be complete.
CRIB = (
    "did you know that julius caesar was not the first person in history "
    "suspected of using encryption me neither did you know that julius caesar "
    "was probably fluent in greek me neither i like how greek character look "
    "though even if i cant read them"
).split()


def build_map(cipher_words, crib_words):
    mapping = {}
    for cw, pw in zip(cipher_words, crib_words):
        cw, pw = cw.strip("?.,!{}'"), pw.strip("?.,!'")
        if len(cw) != len(pw):
            continue
        for c, p in zip(cw, pw):
            mapping[c] = p
    return mapping


def main() -> None:
    ciphertext = open(CHALL, encoding="utf-8").read().strip()
    mapping = build_map(ciphertext.split(), CRIB)
    decoded = "".join(mapping.get(ch, ch) for ch in ciphertext)
    print(decoded)
    match = re.search(r"lactf\{[^}]*\}", decoded)
    print("\nFLAG:", match.group(0) if match else "not found")
```

```console
$ python examples/ch04/solve_greek_cipher.py
did you know that julius caesar was not the first person in history suspected of using encryption? me neither. did you know that julius caesar was probably fluent in greek? me neither. i like how greek character look though, even if i can't read them. lactf{i_guess_using_many_greek_characters_didn't_stop_you._well_played_i_must_say.congrats!}

FLAG: lactf{i_guess_using_many_greek_characters_didn't_stop_you._well_played_i_must_say.congrats!}
```

### Why it worked / generalize

Substitution never hides frequencies or word shapes. A known-plaintext crib — even a guessed one —
pins enough of the map to decrypt the rest. Spot this bug class whenever symbols are relabelled but the
*spacing and structure* of language survive. Unicode glyphs instead of A–Z change nothing: Python
iterates by character, so `{cipher_char: plain_char}` is the same code either way.

## Challenge walkthrough: one-more-time-pad

> Challenge: **one-more-time-pad** — LA CTF 2023 by ACM Cyber at UCLA.
> Source: `uclaacm/lactf-archive@3379d4a7b3` (`2023/crypto/one-more-time-pad`).
> License: MIT (© 2024 ACM at UCLA).

### Recon

```console
$ python challenges/fetch.py one-more-time-pad
$ find challenges/one-more-time-pad -type f
challenges/one-more-time-pad/src/chall.py
challenges/one-more-time-pad/dist/chall.py
challenges/one-more-time-pad/challenge.yaml
```

The source is short (quoted here under fair use for teaching):

```python
from itertools import cycle
pt = b"Long ago, the four nations lived together in harmony ..."
key = cycle(b"lactf{b4by_h1t_m3_0ne_m0r3_t1m3}")
ct = ""
for i in range(len(pt)):
    b = (pt[i] ^ next(key))
    ct += f'{b:02x}'
print("ct =", ct)
#ct = 200e0d13461a055b4e592b0054543902462d1000042b045f1c407f18581b5619...
```

### Clues

> **Clue:** The plaintext is given in the source — `pt = b"Long ago, the four nations…"`. Known
> plaintext.

> **Clue:** The key is wrapped in `itertools.cycle`, so it *repeats*. The ciphertext (55 bytes) is
> longer than the key (32 bytes), so the key wraps around once.

> **Clue:** "one more time **pad**" is a pun — it is not a one-time pad at all, because the pad repeats.
> A repeating key plus known plaintext is an instant crib drag.

Clue → hypothesis: XOR the ciphertext with the known plaintext to recover the keystream. Because the key
repeats every 32 bytes, the first 32 recovered bytes *are* the key — and the key is literally the flag.

### Test the hypothesis

The ciphertext is a hex string on a commented line. Pull it with a regex, decode with
`ctfkit.encoding.from_hex`, and XOR against the plaintext bytes. If the first 32 bytes read as printable
`lactf{...}`, the hypothesis holds.

### Solve

`examples/ch04/solve_one_more_time_pad.py`

```python
import os
import re

from ctfkit.encoding import from_hex, xor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SRC = os.path.join(REPO, "challenges", "one-more-time-pad", "src", "chall.py")

PT = b"Long ago, the four nations lived together in harmony ..."


def main() -> None:
    source = open(SRC).read()
    ct_hex = re.search(r"#ct = ([0-9a-f]+)", source).group(1)
    ct = from_hex(ct_hex)
    keystream = xor(ct, PT)          # known-plaintext XOR -> the repeating key
    key = keystream[:32]             # one period of the key
    print("recovered key:", key.decode())
    print("FLAG:", key.decode())
```

```console
$ python examples/ch04/solve_one_more_time_pad.py
recovered key: lactf{b4by_h1t_m3_0ne_m0r3_t1m3}
FLAG: lactf{b4by_h1t_m3_0ne_m0r3_t1m3}
```

### Why it worked / generalize

A one-time pad is unbreakable **only if the pad is random and used once**. Cycle it and it becomes
repeating-key XOR. With the plaintext known, one XOR recovers the key directly — no key-length guessing.
Watch for `itertools.cycle`, a key shorter than the message, "reuse", or a nonce that never changes. Key
reuse (`crib_drag` above) is the same bug from another angle.

## Summary

- Classical ciphers relabel or shift symbols but preserve structure: frequencies, word shapes, flag
  prefixes. Break them by pulling on that structure.
- Caesar has 26 keys — brute them. Substitution yields to frequency analysis and known-plaintext cribs.
  Vigenère falls once you know the key length (each column is a Caesar).
- XOR is self-inverse, and reused keys cancel. It underlies most CTF crypto.
- Single-byte XOR: brute 256 keys, score for English. Repeating-key XOR: detect the length with Hamming
  distance, then break each column as single-byte XOR.
- **Crib dragging** — XOR a known plaintext fragment against the ciphertext to peel off key bytes — is
  the highest-value XOR skill. Flag prefixes and known quotes are free cribs.
- `ctfkit.crypto` now has `single_byte_xor`, `break_single_byte_xor`, `hamming`, `guess_keysize`, and
  `break_repeating_key_xor`.

## Exercises

1. **Single-byte brute.** This hex was produced by XORing an English sentence with one secret byte.
   Recover the key and the sentence with `ctfkit.crypto`.

   ```text
   5943444d464f0a48535e4f0a5245580a43590a4f4b59530a5e450a48585f5e4f0a4c4558494f
   ```

   <details><summary>Solution</summary>

   ```python
   from ctfkit.crypto import break_single_byte_xor
   ct = bytes.fromhex(
       "5943444d464f0a48535e4f0a5245580a43590a4f4b59530a5e450a48585f5e4f0a4c4558494f")
   key, pt, _ = break_single_byte_xor(ct)
   print(hex(key), pt)
   # 0x2a b'single byte xor is easy to brute force'
   ```

   With a full sentence the English score separates the real key cleanly — unlike a 4-byte sample,
   where many keys tie and you must eyeball the printable candidates.
   </details>

2. **Find the key length — and mind the multiples.** Encrypt a paragraph with a 7-byte key via
   `ctfkit.encoding.xor`, then run `guess_keysize`. You will *not* see 7 on top. Explain why, and
   recover the plaintext anyway.

   <details><summary>Solution</summary>

   ```python
   from ctfkit.crypto import guess_keysize, break_repeating_key_xor
   from ctfkit.encoding import xor
   pt = (b"In a capture the flag event you read the files, you find the clue, and "
         b"then you test a hypothesis against the actual bytes in front of you. "
         b"Repeating key xor is only as strong as the shortest cycle in the key.")
   ct = xor(pt, b"SEVENKY")
   print(guess_keysize(ct))                       # [28, 14, 35] -- all multiples of 7
   k, rec = break_repeating_key_xor(ct, keysize=7)
   print(k, rec == pt)                            # b'SEVENKY' True
   ```

   Any *multiple* of the true key length also makes blocks line up, so 14 and 28 score as well as 7.
   Take the GCD of the top candidates (here 7) and break at that length.
   </details>

3. **Crib-drag a flag prefix.** You intercept this hex — repeating-key XOR of a flag that starts
   `flag{`. Drag the crib to find the key and decrypt.

   ```text
   3e353b56493b2b6b536d3c2b6e565531373d4c
   ```

   <details><summary>Solution</summary>

   ```python
   from ctfkit.encoding import from_hex, xor
   ct = from_hex("3e353b56493b2b6b536d3c2b6e565531373d4c")
   key = xor(ct[:5], b"flag{")          # 5-byte key revealed by the prefix
   print(xor(ct, key).decode())         # flag{cr1b_dr4gging}
   ```

   The 5-byte flag prefix reveals a 5-byte key; cycling it decrypts the rest.
   </details>

4. **Stretch — two-time pad without the plaintext.** Two messages `c1`, `c2` were XORed with the *same*
   unknown keystream. You know only that both are English sentences. XOR `c1 ^ c2` to get `p1 ^ p2`,
   then crib-drag common words (" the ", " and ") across it to recover both plaintexts. Write a helper
   that, given a guessed word at an offset in `p1`, shows the corresponding stretch of `p2`.

   <details><summary>Solution</summary>

   ```python
   from ctfkit.encoding import xor

   def drag(c1, c2, word, offset):
       x = xor(c1, c2)                       # == p1 ^ p2
       guess = xor(x[offset:offset + len(word)], word.encode())
       return bytes(guess)                   # a readable fragment of p2 if the guess is right

   # Slide `word` over every offset; when drag(...) is readable English,
   # you've found that word in p1 and the matching text in p2. Alternate
   # between the two messages, extending known words, until both resolve.
   ```

   This is the classic "many-time pad" attack: the key never appears, but `p1 ^ p2` leaks enough for
   crib dragging to reconstruct both messages.
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-4--classical-ciphers-and-xor)
