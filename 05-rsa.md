# Chapter 5 — RSA from Scratch and Classic Attacks

RSA is the crypto you meet most in CTFs, and almost every RSA challenge is the *same textbook system
with one thing broken*. Learn the plain maths — two primes, a public exponent, a private exponent, two
`pow` calls — and each challenge becomes a game: spot which assumption the author violated. This chapter
builds RSA from scratch with Python's big integers, parses real PEM keys, then keys each classic attack
to the **clue** that reveals it. You grow `ctfkit.crypto` with RSA helpers and solve three real
challenges.

This chapter builds on [Chapter 4](04-classical-and-xor.md) (the `ctfkit.crypto` module, bytes↔int
conversions) and leads into [Chapter 6](06-attacking-randomness.md).

## RSA in one page

RSA is three numbers and two modular exponentiations:

- Pick two large primes `p`, `q`. Set the **modulus** `n = p*q` and `phi = (p-1)*(q-1)` (Euler's
  totient — the count of integers below `n` coprime to it).
- Pick a **public exponent** `e` coprime to `phi` (almost always `65537`). The **private exponent** is
  `d = e^{-1} mod phi`, the modular inverse of `e`.
- Turn the message bytes into an integer `m`. **Encrypt** `c = m^e mod n`. **Decrypt** `m = c^d mod n`.

The public key is `(n, e)`; the private key adds `d` (and usually `p`, `q`). Security rests on one fact:
**recovering `d` requires `phi`, and `phi` requires factoring `n`** — hard for big balanced semiprimes,
easy the moment the author gives you a shortcut.

> **Python makes this trivial.** `pow(base, exp, mod)` does modular exponentiation on thousand-bit
> integers instantly, and `pow(e, -1, m)` (Python 3.8+) is the modular inverse. `int` is
> arbitrary-precision, so there's no "bignum library" to set up — the language *is* the bignum library.

### Modular inverses: the one piece that isn't obvious

Everything else is `+`, `*`, `pow`. The modular inverse — find `d` with `e*d ≡ 1 (mod m)` — comes from
the **extended Euclidean algorithm**: it returns `g, x, y` with `a*x + b*y = gcd(a, b)`, and when
`gcd(e, m) = 1`, that `x` is the inverse. `ctfkit.crypto` ships `egcd` and `modinv`; stdlib
`pow(e, -1, m)` does the same.

`examples/ch05/modmath.py`

```python
from ctfkit.crypto import egcd, modinv


def main() -> None:
    e, phi = 65537, 3120
    g, x, y = egcd(e, phi)
    print(f"egcd({e}, {phi}) = (g={g}, x={x}, y={y})")
    print(f"check: {e}*{x} + {phi}*{y} = {e * x + phi * y}")

    d1 = modinv(e, phi)
    d2 = pow(e, -1, phi)          # stdlib shortcut, Python 3.8+
    print(f"modinv      = {d1}")
    print(f"pow(e,-1,m) = {d2}")
    print(f"e*d mod phi = {e * d1 % phi}")
```

```console
$ python examples/ch05/modmath.py
egcd(65537, 3120) = (g=1, x=-367, y=7709)
check: 65537*-367 + 3120*7709 = 1
modinv      = 2753
pow(e,-1,m) = 2753
e*d mod phi = 1
```

### Keygen, encrypt, decrypt by hand

With `pow` and `modinv`, "RSA from scratch" is a dozen lines. We use PyCryptodome's `getPrime` only to
get large primes quickly; everything else is plain arithmetic. `ctfkit.encoding` converts between the
flag bytes and the integer `m` (`bytes_to_long` / `long_to_bytes` — the CTF-friendly names for
`int.from_bytes` and `int.to_bytes`).

`examples/ch05/rsa_keygen.py`

```python
from Crypto.Util.number import getPrime

from ctfkit.encoding import bytes_to_long, long_to_bytes


def main() -> None:
    p, q = getPrime(512), getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)

    m = bytes_to_long(b"flag{textbook_rsa_is_just_two_pows}")
    c = pow(m, e, n)
    recovered = long_to_bytes(pow(c, d, n))

    print("n bits    :", n.bit_length())
    print("ciphertext:", hex(c)[:50], "...")
    print("recovered :", recovered.decode())
```

```console
$ python examples/ch05/rsa_keygen.py
n bits    : 1024
ciphertext: 0x6e33e9ac80b4ddc69f0308db1ebbaef9f89e5510c26c2acb ...
recovered : flag{textbook_rsa_is_just_two_pows}
```

> **"Textbook" RSA has no padding.** Real RSA pads the message (OAEP/PKCS#1 v1.5) before exponentiating.
> CTF challenges usually skip padding — which is what makes the small-`e` and other attacks below
> possible. If a challenge *does* pad, the raw-integer attacks won't apply.

### Reading real keys: PEM parsing

Challenges hand you keys as PEM or DER files, not Python integers. PyCryptodome's `RSA.importKey` (alias
`RSA.import_key`) parses either, and the object exposes `.n`, `.e`, and — for private keys — `.d`.

`examples/ch05/pem_parse.py`

```python
from Crypto.PublicKey import RSA


def main() -> None:
    key = RSA.generate(1024)
    pem = key.export_key()                 # PEM bytes, as shipped in a challenge
    print(pem.decode().splitlines()[0])    # -----BEGIN RSA PRIVATE KEY-----

    loaded = RSA.importKey(pem)
    print("n bits:", loaded.n.bit_length())
    print("e     :", loaded.e)
    print("has d :", hasattr(loaded, "d"))

    pub = RSA.importKey(key.publickey().export_key())
    print("public has_private:", pub.has_private())
```

```console
$ python examples/ch05/pem_parse.py
-----BEGIN RSA PRIVATE KEY-----
n bits: 1024
e     : 65537
has d : True
public has_private: False
```

That `RSA.importKey(...).d` is the entire first challenge below.

## Attacks keyed to their clue

Each attack exists because the author broke one assumption. Read the public parameters as a checklist.

| Clue in the challenge | Broken assumption | Attack |
|-----------------------|-------------------|--------|
| A `private.pem` / `d` is given | nothing — you have the key | decrypt: `m = c^d mod n` |
| `n` is prime (not a semiprime) | `n` should be hard to factor | `phi = n - 1` directly |
| `e` is tiny (3) and `m` is short | message padded so `m^e >= n` | integer `e`-th root of `c` |
| `p`, `q` are close in size | primes should be far apart | Fermat factorisation |
| `n` is small | `n` should be ~2048 bits | just factor it (`sympy.factorint`) |
| Leaks like `a*p + b*q` | factors fully secret | GCD / lattice from the hints |

### Small `e`, no padding: take a root

If `e = 3` and the message is short, `m^3` can be smaller than `n`. Then `c = m^3 mod n` never wraps —
`c` is literally `m^3`, and `m` is its exact cube root. No factoring, no key. `cube_root`/`iroot`
(integer `k`-th root via binary search) and `rsa_attack_small_e` handle it.

`examples/ch05/small_e.py`

```python
from Crypto.Util.number import getPrime

from ctfkit.crypto import rsa_attack_small_e
from ctfkit.encoding import bytes_to_long


def main() -> None:
    e = 3
    n = getPrime(1024) * getPrime(1024)        # a big modulus
    m = bytes_to_long(b"flag{cube_root_me}")   # short message
    c = pow(m, e, n)

    print("m^e < n :", m ** e < n)             # True -> no reduction happened
    print("recovered:", rsa_attack_small_e(c, e, n).decode())
```

```console
$ python examples/ch05/small_e.py
m^e < n : True
recovered: flag{cube_root_me}
```

If `m^e` *did* wrap, `c = m^e + k*n` for some small `k`; `rsa_attack_small_e` also tries adding
multiples of `n` before taking the root.

### Factoring weak moduli: Fermat and sympy

Two cheap ways to factor a bad `n`:

- **Close primes.** If `p` and `q` are near each other (two halves of a flag, or `q = nextprime(p)`),
  Fermat's method writes `n = a^2 - b^2 = (a-b)(a+b)` by scanning `a` upward from `isqrt(n)` until
  `a^2 - n` is a perfect square. It finds them in a handful of steps. `ctfkit.crypto.factor_fermat`.
- **Small `n`.** A short modulus just factors. `sympy.factorint` is the practitioner tool.

`examples/ch05/factoring.py`

```python
from sympy import factorint, nextprime

from ctfkit.crypto import factor_fermat


def main() -> None:
    p = nextprime(10 ** 30)
    q = nextprime(p)                   # adjacent prime: tiny gap
    n = p * q
    fp, fq = factor_fermat(n)
    print("Fermat  :", fp, fq, " ok=", {fp, fq} == {int(p), int(q)})

    small_n = 0xC0FFEE1234567
    print("factorint:", factorint(small_n))
```

```console
$ python examples/ch05/factoring.py
Fermat  : 1000000000000000000000000000057 1000000000000000000000000000099  ok= True
factorint: {19: 1, 127: 1, 1801: 1, 9227: 1, 84673: 1}
```

Once you have `p` and `q`, rebuild `phi = (p-1)*(q-1)`, compute `d = pow(e, -1, phi)`, and decrypt —
textbook RSA again.

## Building ctfkit: `ctfkit.crypto` (RSA)

This chapter *grows* `crypto.py`: keep Chapter 4's XOR functions and append the RSA machinery. Extend
`__all__` and add the functions after the XOR section.

`project/ch05/ctfkit/crypto.py` (new RSA section)

```python
def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclid: return (g, x, y) with a*x + b*y == g."""
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m (raises if none exists)."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m}")
    return x % m


def iroot(n: int, k: int) -> tuple[int, bool]:
    """Integer k-th root of n: (root, exact) via binary search."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return (0, True)
    lo, hi = 1, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return (lo, lo ** k == n)


def cube_root(n: int) -> tuple[int, bool]:
    """Integer cube root; (root, exact). The e=3 no-padding attack."""
    return iroot(n, 3)
```

The attacks are small, and each names its clue:

```python
def rsa_decrypt(c: int, d: int, n: int) -> bytes:
    """Textbook decrypt with private exponent d: m = c^d mod n."""
    return long_to_bytes(pow(c, d, n))


def factor_fermat(n: int, max_steps: int = 1_000_000) -> tuple[int, int]:
    """Fermat factorisation: fast when p and q are close (n = a^2 - b^2)."""
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
    """n prime -> phi = n - 1, so d = e^{-1} mod (n-1). No factoring."""
    d = modinv(e, n - 1)
    return rsa_decrypt(c, d, n)


def rsa_attack_small_e(c: int, e: int, n: int | None = None) -> bytes:
    """Small e, no padding: if m^e < n then m is a plain e-th root of c."""
    root, exact = iroot(c, e)
    if exact:
        return long_to_bytes(root)
    if n is not None:                      # maybe m^e wrapped: try c + k*n
        k = 1
        while k < 1_000_000:
            root, exact = iroot(c + k * n, e)
            if exact:
                return long_to_bytes(root)
            k += 1
    raise ValueError("no exact e-th root found; message may be padded or e too large")
```

Add `egcd`, `modinv`, `cube_root`, `iroot`, `rsa_decrypt`, `factor_fermat`,
`rsa_attack_prime_modulus`, and `rsa_attack_small_e` to `__all__`, then the tests:

```python
def test_modinv_and_egcd():
    assert c.modinv(3, 11) == 4
    g, x, y = c.egcd(240, 46)
    assert 240 * x + 46 * y == g == 2


def test_iroot_and_cube_root():
    assert c.iroot(27, 3) == (3, True)
    assert c.iroot(28, 3) == (3, False)
    assert c.cube_root(8) == (2, True)


def test_fermat_factor_balanced():
    p, q = 1000003, 1000033
    assert {*c.factor_fermat(p * q)} == {p, q}


def test_rsa_prime_modulus_attack():
    n, e_ = 2 ** 127 - 1, 65537          # a Mersenne prime modulus
    m = int.from_bytes(b"flag{hi}", "big")
    assert c.rsa_attack_prime_modulus(pow(m, e_, n), e_, n) == b"flag{hi}"


def test_rsa_small_e_cube_root():
    m = int.from_bytes(b"short-secret", "big")
    assert c.rsa_attack_small_e(m ** 3, 3) == b"short-secret"
```

### Checkpoint

```console
$ cd project/ch05 && python -m pytest -q
.............                                                            [100%]
13 passed in 0.02s
```

Thirteen pass (eight from Chapter 4 plus five RSA tests). The complete project at this point is in
`project/ch05/`.

## Challenge walkthrough: rsa (you were handed the private key)

> Challenge: **rsa** — ImaginaryCTF 2023 by Eth007.
> Source: `ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026` (`Crypto/rsa`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py rsa
$ ls challenges/rsa/challenge
flag.enc  private.pem  public.pem  solve.py
$ file challenges/rsa/challenge/flag.enc
flag.enc: data
$ head -1 challenges/rsa/challenge/public.pem
-----BEGIN PUBLIC KEY-----
```

A public key, a **private** key, and an encrypted flag. The prompt is just "I think I did my RSA
right…".

### Clues

> **Clue:** The distribution includes `private.pem`. In RSA, the private key is the whole secret — if
> you have `d` (and `n`), there is no attack. This challenge teaches the machinery, not a break.

Clue → hypothesis: import the private key, read `d` and `n`, read the ciphertext integer from
`flag.enc`, and compute `m = c^d mod n`.

### Test the hypothesis

`flag.enc` is raw bytes, not text — read it as `bytes` and convert to an integer with `bytes_to_long`.
`RSA.importKey` on `private.pem` gives `.d` and `.n`. One `pow` should produce printable ASCII starting
`ictf{`.

### Solve

`examples/ch05/solve_rsa.py`

```python
import os

from Crypto.PublicKey import RSA

from ctfkit.crypto import rsa_decrypt
from ctfkit.encoding import bytes_to_long

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
BASE = os.path.join(REPO, "challenges", "rsa", "challenge")


def main() -> None:
    key = RSA.importKey(open(os.path.join(BASE, "private.pem"), "rb").read())
    c = bytes_to_long(open(os.path.join(BASE, "flag.enc"), "rb").read())
    flag = rsa_decrypt(c, key.d, key.n)
    print("FLAG:", flag.decode())
```

```console
$ python examples/ch05/solve_rsa.py
FLAG: ictf{keep_your_private_keys_private}
```

### Why it worked / generalize

There was nothing to break — possessing the private key *is* the solution. The real skills: read a PEM
with PyCryptodome and turn a binary ciphertext file into the integer `c`. Whenever a challenge hands you
`private.pem`, `d`, or enough to compute `phi`, stop hunting for a clever attack and just decrypt.

## Challenge walkthrough: Primary Knowledge (a prime modulus)

> Challenge: **primary-knowledge** ([Very Easy] Primary Knowledge) — HTB Cyber Apocalypse 2024 by
> HackTheBox. Source: `hackthebox/cyber-apocalypse-2024@4e59eec7a4`
> (`crypto/[Very Easy] Primary Knowledge`). License: none (HTB official write-up repo).

### Recon

```console
$ python challenges/fetch.py primary-knowledge
$ cat challenges/primary-knowledge/htb/output.txt
n = 1445957840221870522381252624582329591099871367042312458818707358430309...
e = 65537
c = 15114190905253542247495696649766224943647565245575793033722173362381895...
```

Just `n`, `e`, `c` — no PEM, no source. The name "Primary **Knowledge**" is a hint in plain sight.

### Clues

> **Clue:** Normal RSA needs you to factor `n` into two primes. Try it and `n` won't split — because
> `n` is *itself prime*. (The pun: "primary" = prime.)

> **Clue:** If `n` is prime, Euler's totient is `phi = n - 1` directly (for a prime `p`,
> `phi(p) = p - 1`). No factoring needed — compute `d = e^{-1} mod (n - 1)` and decrypt.

Clue → hypothesis: verify `n` is prime, set `phi = n - 1`, invert `e`, decrypt.

### Test the hypothesis

`sympy.isprime(n)` confirms the clue before committing. If `True`, `rsa_attack_prime_modulus` does the
rest: `d = modinv(e, n - 1)` then `c^d mod n`.

### Solve

`examples/ch05/solve_primary_knowledge.py`

```python
import os

from sympy import isprime

from ctfkit.crypto import rsa_attack_prime_modulus

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTPUT = os.path.join(REPO, "challenges", "primary-knowledge", "htb", "output.txt")


def main() -> None:
    env: dict = {}
    exec(open(OUTPUT).read(), env)        # defines n, e, c
    n, e, c = env["n"], env["e"], env["c"]
    assert isprime(n), "clue was wrong: n is not prime"
    print("n is prime -> phi = n - 1, no factoring needed")
    print("FLAG:", rsa_attack_prime_modulus(c, e, n).decode())
```

> **Python idiom.** `output.txt` is already valid Python (`n = …`, `e = …`, `c = …`), so
> `exec(open(...).read(), env)` runs it and the three variables land in `env`. This is a common,
> quick way to load a challenge's printed parameters — safe here because the file is a trusted,
> pinned artifact you just inspected.

```console
$ python examples/ch05/solve_primary_knowledge.py
n is prime -> phi = n - 1, no factoring needed
FLAG: HTB{0h_d4mn_4ny7h1ng_r41s3d_t0_0_1s_1!!!}
```

### Why it worked / generalize

RSA's hardness is the hardness of factoring `n`. A prime `n` has a totient you can write down —
`phi = n - 1` — so the private key falls out in one inversion. Always sanity-check the modulus:
`isprime(n)`, and watch for a tiny or lopsided `n` that `sympy.factorint` can split. A "modulus" that
isn't a product of two big primes is a free win.

## Challenge walkthrough: apbq-rsa-i (linear hints → GCD)

> Challenge: **apbq-rsa-i** — DownUnderCTF 2023 by the DUCTF organisers (joseph).
> Source: `DownUnderCTF/Challenges_2023_Public@b48f83db29` (`crypto/apbq-rsa-i`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py apbq-rsa-i
$ find challenges/apbq-rsa-i/src -type f
challenges/apbq-rsa-i/src/apbq-rsa-i.py
challenges/apbq-rsa-i/src/output.txt
challenges/apbq-rsa-i/src/flag.txt
```

The source shows how the "hints" are built (quoted for teaching):

```python
p, q = getPrime(1024), getPrime(1024)
n, e = p * q, 0x10001
hints = []
for _ in range(2):
    a, b = randint(0, 2**12), randint(0, 2**312)
    hints.append(a * p + b * q)
c = pow(bytes_to_long(FLAG), e, n)
```

And `output.txt` prints `n`, `c`, and `hints` (two big integers). The bundled `HINTS.md` spells the
path out: "the `a` values are small — bruteforce" and "look into GCD."

### Clues

> **Clue:** Each hint is `a*p + b*q` with `a < 2**12` (only 4096 values) but `b < 2**312` (huge,
> unguessable). The small coefficient is the lever.

> **Clue:** For two hints `h0 = a0*p + b0*q` and `h1 = a1*p + b1*q`, the combination
> `a1*h0 - a0*h1 = (a1*b0 - a0*b1)*q` — the `p` terms cancel, leaving a multiple of `q`. Then
> `gcd(that, n)` reveals `q`.

Clue → hypothesis: brute the two small coefficients `a0, a1` in `[1, 4096)`. For the right pair,
`gcd(a1*h0 - a0*h1, n)` is a non-trivial factor of `n`.

### Test the hypothesis

`gcd(k, n)` returns 1 for most `(a0, a1)` and `n` itself for a few degenerate ones; a value strictly
between `1` and `n` is a real factor. The recovered `g` may carry the extra scalar `(a1*b0 - a0*b1)`, so
divide out small cofactors until `n % g == 0` cleanly. This is a deliberate ~25-second brute, not the
lattice solution — the point is "GCD is a good algorithm for the toolbox," which is literally the flag.

### Solve

`examples/ch05/solve_apbq_rsa_i.py`

```python
import os
from math import gcd

from ctfkit.encoding import long_to_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTPUT = os.path.join(REPO, "challenges", "apbq-rsa-i", "src", "output.txt")
E = 0x10001


def recover_q(n, h0, h1, bound=4096):
    for a1 in range(1, bound):
        a1h0 = a1 * h0
        for a0 in range(1, bound):
            g = gcd(a1h0 - a0 * h1, n)
            if 1 < g < n:
                return g
    raise RuntimeError("no coefficient pair found")


def main() -> None:
    env: dict = {}
    exec(open(OUTPUT).read(), env)            # defines n, c, hints
    n, c, hints = env["n"], env["c"], env["hints"]
    kq = recover_q(n, hints[0], hints[1])
    for i in range(2 ** 16, 1, -1):           # strip the (a1 b0 - a0 b1) cofactor
        while kq % i == 0 and kq // i > 1 and n % (kq // i) == 0:
            kq //= i
    q = kq
    p = n // q
    assert p * q == n, "factorisation failed"
    d = pow(E, -1, (p - 1) * (q - 1))
    print("FLAG:", long_to_bytes(pow(c, d, n)).decode())
```

```console
$ python examples/ch05/solve_apbq_rsa_i.py
FLAG: DUCTF{gcd_1s_a_g00d_alg0r1thm_f0r_th3_t00lbox}
```

> **⚠ Timing.** The double loop over `a0, a1` runs in about 25 seconds here and depends on your CPU;
> it is a brute force, not a constant-time step. A lattice (LLL) solve would be instant but is beyond
> this chapter — the brute is the teachable, dependency-free path.

### Why it worked / generalize

When secret factors leak through a *linear* relation with small coefficients, you can cancel one factor
and recover the other with a GCD. The pattern — "small unknowns + a linear equation in `p, q` ⇒ brute
the smalls, GCD out a factor" — recurs across crypto challenges. GCD and the extended Euclidean
algorithm are two of the most reusable crypto tools; reach for them whenever you see sums or differences
of the secret primes.

## Summary

- RSA is two primes, `e`, `d = e^{-1} mod phi`, and two `pow` calls. Python's arbitrary-precision
  `int`, `pow(c, d, n)`, and `pow(e, -1, m)` give you the whole system for free.
- Read the public parameters as a checklist. Each classic attack is one broken assumption: a given
  private key, a prime `n`, a tiny `e` with no padding, close primes, a small `n`, or linear leaks.
- `RSA.importKey` parses PEM/DER keys; `.n`, `.e`, `.d` are the integers you need.
- `ctfkit.crypto` now also has `egcd`, `modinv`, `iroot`/`cube_root`, `rsa_decrypt`, `factor_fermat`,
  `rsa_attack_prime_modulus`, and `rsa_attack_small_e`.
- The meta-skill: sanity-check `n` (prime? small? close primes?) and `e` (tiny?) *before* reaching for
  anything advanced.

## Exercises

1. **Cube-root a flag.** With `e = 3`, a short flag `m` was encrypted as `c = m**3` (no modular
   reduction). Given `c = 113155621913745749224713705810592751112402246467710769457150213043024997`,
   recover the flag.

   <details><summary>Solution</summary>

   ```python
   from ctfkit.crypto import rsa_attack_small_e
   c = 113155621913745749224713705810592751112402246467710769457150213043024997
   print(rsa_attack_small_e(c, 3).decode())   # flag{cube}
   ```

   Because `m**3 < n`, the ciphertext is a perfect cube and `iroot(c, 3)` is exact.
   </details>

2. **Factor and decrypt.** You are given `n`, `e = 65537`, and `c` where `n` is a product of two
   *close* primes. Use `factor_fermat` to split `n`, then decrypt.

   <details><summary>Solution</summary>

   ```python
   from Crypto.Util.number import getPrime, bytes_to_long
   from sympy import nextprime
   from ctfkit.crypto import factor_fermat, rsa_decrypt

   p = getPrime(512); q = nextprime(p)
   n, e = p * q, 65537
   c = pow(bytes_to_long(b"flag{fermat_eats_close_primes}"), e, n)

   fp, fq = factor_fermat(n)
   d = pow(e, -1, (fp - 1) * (fq - 1))
   print(rsa_decrypt(c, d, n).decode())
   ```

   Fermat converges in a few steps because `q = nextprime(p)` makes the gap tiny.
   </details>

3. **Same message, two moduli (Håstad warm-up).** A sender encrypts the *same* short `m` under `e = 3`
   with three different moduli `n1, n2, n3` (each too large for a plain cube root). Explain how the
   Chinese Remainder Theorem recovers `m`, and sketch the code using `sympy`.

   <details><summary>Solution</summary>

   CRT combines `c1, c2, c3` into `C ≡ m^3 (mod n1*n2*n3)`. Since `m^3 < n1*n2*n3`, `C` *is* `m^3` as an
   integer, so take the exact cube root:

   ```python
   from sympy.ntheory.modular import crt
   from ctfkit.crypto import iroot
   from ctfkit.encoding import long_to_bytes

   C, _ = crt([n1, n2, n3], [c1, c2, c3])
   root, exact = iroot(int(C), 3)
   assert exact
   print(long_to_bytes(root))
   ```

   This is Håstad's broadcast attack: a small `e` reused across enough moduli leaks the message.
   </details>

4. **Stretch — apbq-rsa-ii.** The sibling challenge `apbq-rsa-ii` leaks three hints with larger
   coefficients, defeating the simple double brute. Fetch it (`python challenges/fetch.py apbq-rsa-ii`),
   read `HINTS.md`, and research the lattice (LLL) approach. Describe why three leaks and a short vector
   in a cleverly built lattice recover `p, q` where brute force cannot.

   <details><summary>Solution</summary>

   With coefficients too large to brute, you instead build a lattice whose rows encode the hint
   equations and the relation `n = p*q`; LLL finds a short vector corresponding to the small unknowns,
   revealing a factor. The takeaway: "small unknowns in linear relations" generalises from GCD (two
   small coefficients) to lattice reduction (several, or larger, unknowns). This is the standard upgrade
   path for `a*p + b*q`-style leaks and a good gateway into using `fpylll`/Sage for CTF lattices.
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-5--rsa-from-scratch-and-classic-attacks)
