# Chapter 6 — Predicting "Random" Numbers

"Random" is a lie CTF authors tell constantly. Python's `random` is a **Mersenne Twister** — great for
simulations, catastrophic for secrets, because every value is a deterministic function of an internal
state you can often reconstruct. This chapter shows how predictable the common generators are — small
seeds, LCGs, LFSRs, and MT19937 itself — and recovers each in pure Python, no SageMath. You grow
`ctfkit.crypto` with an `MT19937` predictor and an `LFSR`, then use them against a real service.

This chapter builds on [Chapter 4](04-classical-and-xor.md)/[Chapter 5](05-rsa.md) (the `ctfkit.crypto`
module) and [Chapter 3](03-talking-to-services.md) (driving a local service with pwntools). Next is
[Chapter 7](07-python-reversing.md).

## Why `random` is not random enough

The rule: **a PRNG is predictable if you can recover its state, and you can recover its state whenever
it leaks enough output.** How much is "enough" depends on the generator.

| Generator | State | Breaks when you see… |
|-----------|-------|----------------------|
| Small seed (`seed = randbits(16)`) | the seed | a few outputs → brute every seed |
| LCG `x = a*x + c mod m` | one integer | ~3 consecutive outputs (solve for `a, c`) |
| LFSR (width `w`) | `w` bits | `w` output bits (linear over GF(2)) |
| MT19937 (`random`) | 624 words | 624 consecutive 32-bit outputs (untemper) |

None of these are cryptographic. The secure answer is `secrets` / `os.urandom`; this chapter is about
recognising when a challenge used the insecure one.

### Seeding: determinism is the whole vulnerability

`random.seed(x)` makes the entire stream a function of `x` — re-seed with the same value, get the same
numbers. If the seed space is small (a 16-bit value, a PID, a timestamp), brute every seed offline and
keep the one whose output matches what you saw. That is the attack behind `randomly-chosen` in
[Chapter 3](03-talking-to-services.md), generalised here.

`examples/ch06/seed_brute.py`

```python
import random


def main() -> None:
    random.seed(1337)
    a = [random.randint(0, 999) for _ in range(5)]
    random.seed(1337)
    b = [random.randint(0, 999) for _ in range(5)]
    print("reproducible:", a == b, a)

    secret = 0xBEEF & 0xFFFF            # a service seeds with a 16-bit secret
    random.seed(secret)
    leak = [random.getrandbits(16) for _ in range(3)]

    for guess in range(1 << 16):       # brute all 65536 seeds offline
        random.seed(guess)
        if [random.getrandbits(16) for _ in range(3)] == leak:
            print("recovered seed:", hex(guess))
            break
```

```console
$ python examples/ch06/seed_brute.py
reproducible: True [632, 947, 546, 726, 374]
recovered seed: 0xbeef
```

### LCGs: three outputs and a modular inverse

A linear congruential generator is `x = (a*x + c) mod m`. It is linear, so it keeps no secrets once you
see its outputs. Know `m` and three consecutive values and you solve for `a` and `c`:
`a = (x2 - x1) * (x1 - x0)^{-1} mod m`, then `c = x1 - a*x0`. The modular inverse is the `modinv` from
Chapter 5 (or `pow(_, -1, m)`).

`examples/ch06/lcg.py`

```python
class LCG:
    def __init__(self, seed, a, c, m):
        self.state, self.a, self.c, self.m = seed, a, c, m

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state


def recover_a_c(outputs, m):
    x0, x1, x2 = outputs[:3]
    a = (x2 - x1) * pow(x1 - x0, -1, m) % m
    c = (x1 - a * x0) % m
    return a, c


def main() -> None:
    m = 2 ** 31 - 1
    gen = LCG(seed=123456789, a=1103515245, c=12345, m=m)
    outputs = [gen.next() for _ in range(6)]
    print("observed:", outputs[:4], "...")

    a, c = recover_a_c(outputs, m)
    print(f"recovered a={a}, c={c}")
    clone = LCG(seed=outputs[2], a=a, c=c, m=m)
    predicted = [clone.next() for _ in range(3)]
    print("predicted:", predicted)
    print("actual   :", outputs[3:])
    print("match    :", predicted == outputs[3:])
```

```console
$ python examples/ch06/lcg.py
observed: [295234770, 465300796, 1475666158, 588454008] ...
recovered a=1103515245, c=12345
predicted: [588454008, 929838277, 50298429]
actual   : [588454008, 929838277, 50298429]
match    : True
```

If `m` is also unknown, recover it too: build several values `t_i = x_{i+1} - x_i`, then `m` divides
many `t_{i+1}*t_{i-1} - t_i^2`, so a GCD of those reveals it. The lesson stays the same — linear means
predictable.

### LFSRs: linear feedback over GF(2)

A linear-feedback shift register shifts one bit out per clock and feeds a XOR of "tap" positions back
in. Because every bit is a XOR, the output is a *linear function of the initial register over GF(2)* — so
watching as many output bits as the register is wide reconstructs the state. `ctfkit.crypto.LFSR` clocks
the register's last bit out, so the first `width` outputs are the initial state in shift-out (reversed)
order; `recover_state` reverses them back. From the recovered state you clock forward to predict.

`examples/ch06/lfsr.py`

```python
from ctfkit.crypto import LFSR


def main() -> None:
    taps, width, secret = [0, 2], 5, [1, 0, 1, 1, 0]   # feedback = state[0]^state[2]
    gen = LFSR(list(secret), taps)
    observed = gen.bits(width)             # attacker sees these output bits
    print("output bits:", observed)

    recovered = LFSR.recover_state(observed, taps, width)
    print("recovered  :", recovered, " match=", recovered == secret)

    clone = LFSR(recovered, taps)
    clone.bits(width)                      # fast-forward past what we already saw
    truth = LFSR(list(secret), taps)
    truth.bits(width)
    predicted = clone.bits(6)
    actual = truth.bits(6)
    print("predicted  :", predicted)
    print("actual     :", actual, " match=", predicted == actual)
```

```console
$ python examples/ch06/lfsr.py
output bits: [0, 1, 1, 0, 1]
recovered  : [1, 0, 1, 1, 0]  match= True
predicted  : [0, 0, 1, 1, 1, 0]
actual     : [0, 0, 1, 1, 1, 0]  match= True
```

> **GF(2) is just XOR algebra.** "Solving a linear system over GF(2)" means Gaussian elimination where
> `+` is XOR and every value is 0 or 1. For a general LFSR with unknown taps, build one XOR equation per
> observed bit and solve the matrix; for the simple Fibonacci register here, the first `width` outputs
> already *are* the state (reversed), so no matrix is needed. The same GF(2) idea scales all the way up
> to MT19937's 19937-bit state (the `encrypted-mail` note at the end).

## MT19937: cloning Python's `random`

Python's `random` is a Mersenne Twister with a **624-word** (624 × 32-bit) state. Each output is one
state word pushed through a reversible **tempering** — four shift/XOR/mask steps:

```python
y ^= y >> 11
y ^= (y << 7) & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= y >> 18
```

Every step is invertible, so you can **untemper** an output back into the state word that produced it.
Collect 624 consecutive outputs, untemper each, and you have the whole state — then clone the generator
and predict every future value exactly. No seed, no factoring.

`examples/ch06/mt_predict.py`

```python
import random

from ctfkit.crypto import MT19937, untemper


def main() -> None:
    def temper(y):
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF

    print("untemper inverts temper:", untemper(temper(0xDEADBEEF)) == 0xDEADBEEF)

    random.seed()                                   # unknown, fresh state
    observed = [random.getrandbits(32) for _ in range(624)]
    predictor = MT19937.from_outputs(observed)

    predicted = [predictor.next_u32() for _ in range(5)]
    actual = [random.getrandbits(32) for _ in range(5)]
    print("predicted:", predicted)
    print("actual   :", actual)
    print("match    :", predicted == actual)
```

```console
$ python examples/ch06/mt_predict.py
untemper inverts temper: True
predicted: [2717452686, 401523955, 1995303244, 1497826782, 2091318268]
actual   : [2717452686, 401523955, 1995303244, 1497826782, 2091318268]
match    : True
```

(The exact numbers are ⚠ random — they change every run. What never changes is `match: True`.)

> **Why untempering works.** Each tempering step mixes a value with a *shifted* copy of itself. A right
> shift leaves the top bits untouched, so you recover them first and use them to peel the next bits; a
> left shift leaves the bottom bits untouched, so you go the other way. `ctfkit`'s `_undo_rshift_xor`
> and `_undo_lshift_xor` do exactly this bit-by-bit.

### The `random.random()` subtlety (why `encrypted-mail` is hard)

`getrandbits(32)` leaks a whole state word per call — ideal for untempering. But `random.random()` is
different: it builds a 53-bit float from **two** state words, `a = next >> 5` (27 bits) and
`b = next >> 6` (26 bits), as `(a * 2**26 + b) / 2**53`. `ctfkit.crypto.MT19937` reproduces this in
`.random()` and seeds exactly like CPython in `from_seed`, so a clone matches the real stream.

`examples/ch06/mt_random.py`

```python
import random

from ctfkit.crypto import MT19937


def main() -> None:
    mine = MT19937.from_seed(2024)
    random.seed(2024)
    print("floats match:", [mine.random() for _ in range(3)] == [random.random() for _ in range(3)])

    mt = MT19937.from_seed(2024)
    f = mt.random()
    print("one random() =", f, "-> round ->", round(f))
    print("that call consumed 2 of the 624 state words")
```

```console
$ python examples/ch06/mt_random.py
floats match: True
one random() = 0.47009071843107064 -> round -> 0
that call consumed 2 of the 624 state words
```

This matters because a challenge that only leaks `round(random.random())` gives you **one bit** after
burning two whole state words — you cannot untemper that. Recovering the state becomes a GF(2) linear
solve over many single-bit leaks, exactly the wall `encrypted-mail` puts up (last section).

## Building ctfkit: `ctfkit.crypto` (PRNG recovery)

This chapter finishes `crypto.py` by appending the PRNG tools to the XOR (Chapter 4) and RSA
(Chapter 5) code. Add `untemper`, `MT19937`, and `LFSR` to `__all__`.

The untemper helpers invert the two shift directions; `untemper` applies the four inverse steps in
reverse order:

`project/ch06/ctfkit/crypto.py` (new PRNG section, excerpt)

```python
_MT_MASK32 = 0xFFFFFFFF


def _undo_rshift_xor(y: int, shift: int, mask: int = _MT_MASK32) -> int:
    """Invert y = x ^ ((x >> shift) & mask), reconstructing from the top."""
    x = 0
    for i in range(32):
        bit = 31 - i
        src = bit + shift
        known = (x >> src) & 1 if src < 32 else 0
        xbit = ((y >> bit) & 1) ^ (known & ((mask >> bit) & 1))
        x |= xbit << bit
    return x & _MT_MASK32


def _undo_lshift_xor(y: int, shift: int, mask: int) -> int:
    """Invert y = x ^ ((x << shift) & mask), reconstructing from the bottom."""
    x = 0
    for bit in range(32):
        src = bit - shift
        known = (x >> src) & 1 if src >= 0 else 0
        xbit = ((y >> bit) & 1) ^ (known & ((mask >> bit) & 1))
        x |= xbit << bit
    return x & _MT_MASK32


def untemper(y: int) -> int:
    """Invert MT19937's output tempering to recover one internal state word."""
    y = _undo_rshift_xor(y, 18)
    y = _undo_lshift_xor(y, 15, 0xEFC60000)
    y = _undo_lshift_xor(y, 7, 0x9D2C5680)
    y = _undo_rshift_xor(y, 11)
    return y & _MT_MASK32
```

The `MT19937` class stores the 624-word state and reproduces CPython's twist and tempering.
`from_outputs` rebuilds the state from 624 tempered outputs; `next_u32` and `random` generate forward:

```python
class MT19937:
    def __init__(self, state=None, index=624):
        self.mt = list(state) if state is not None else [0] * 624
        self.index = index

    @classmethod
    def from_outputs(cls, outputs):
        """Build a generator from 624 tempered 32-bit outputs."""
        state = [untemper(y) for y in outputs]
        if len(state) != 624:
            raise ValueError(f"need exactly 624 outputs, got {len(state)}")
        return cls(state, index=624)        # index=624 forces a twist on first call

    def _twist(self):
        for i in range(624):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7FFFFFFF)
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= 0x9908B0DF
        self.index = 0

    def next_u32(self):
        if self.index >= 624:
            self._twist()
        y = self.mt[self.index]
        self.index += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF

    def random(self):
        """Reproduce CPython random.random(): a 53-bit float in [0, 1)."""
        a, b = self.next_u32() >> 5, self.next_u32() >> 6
        return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0)
```

`MT19937` also has `from_seed`, mirroring CPython's `init_by_array`, so you can match a stream when you
know the seed (full body in `project/ch06/ctfkit/crypto.py`). The `LFSR` class clocks the register,
exposes `bits(n)`, and `recover_state` returns the initial state from the first `width` outputs:

```python
class LFSR:
    def __init__(self, state, taps):
        self.state, self.taps = list(state), list(taps)

    def clock(self):
        out = self.state[-1]
        feedback = 0
        for t in self.taps:
            feedback ^= self.state[t]
        self.state = [feedback] + self.state[:-1]
        return out

    def bits(self, n):
        return [self.clock() for _ in range(n)]

    @staticmethod
    def recover_state(outputs, taps, width):
        """First `width` outputs are the start state in shift-out (reversed) order."""
        if len(outputs) < width:
            raise ValueError(f"need at least {width} output bits")
        return list(outputs[:width])[::-1]
```

Add tests covering untempering, forward prediction, the CPython float match, and the LFSR round-trip:

```python
def test_mt19937_predicts_getrandbits():
    random.seed(20240101)
    outs = [random.getrandbits(32) for _ in range(624)]
    mt = c.MT19937.from_outputs(outs)
    assert [mt.next_u32() for _ in range(10)] == [random.getrandbits(32) for _ in range(10)]


def test_mt19937_from_seed_matches_cpython():
    mine = c.MT19937.from_seed(42)
    random.seed(42)
    assert [mine.random() for _ in range(5)] == [random.random() for _ in range(5)]


def test_lfsr_recover_state_round_trips():
    taps, width, secret = [0, 2], 5, [1, 0, 1, 1, 0]
    outputs = c.LFSR(list(secret), taps).bits(width)
    recovered = c.LFSR.recover_state(outputs, taps, width)
    assert recovered == secret            # reversed shift-out order, not outputs as-is
    clone = c.LFSR(recovered, taps); clone.bits(width)
    truth = c.LFSR(list(secret), taps); truth.bits(width)
    assert clone.bits(8) == truth.bits(8)
```

### Checkpoint

```console
$ cd project/ch06 && python -m pytest -q
.................                                                        [100%]
17 passed in 0.03s
```

Seventeen pass (thirteen from Chapters 4–5 plus four PRNG tests). The complete project at this point is
in `project/ch06/`.

## Challenge walkthrough: pprngc

> Challenge: **pprngc** — LA CTF 2024 by ACM Cyber at UCLA.
> Source: `uclaacm/lactf-archive@3379d4a7b3` (`2024/crypto/pprngc`).
> License: MIT (© 2024 ACM at UCLA).

### Recon

```console
$ python challenges/fetch.py pprngc
$ ls challenges/pprngc
Dockerfile  challenge.yaml  pprngc.py  solve.py  super_secret_stuff.py
$ python challenges/pprngc/pprngc.py
All you need to know about f is that it's a function from 16 bits to 16 bits
The output on today's secret seed is: 41657
What can I do for you? 1. get random bits 2. use f 3. predict next bit 4. guess seed
```

The service (quoted for teaching) builds a 16-bit state update `f` from a length-7 LFSR, a length-5
LFSR, and a 4-bit counter over a secret bit **permutation**, then offers four options:

```python
seed = secrets.randbits(16)

def compute_output_bit(state, pred):
    return bin((state & pred)).count("1") % 2            # parity of selected bits

def pprngc(pred, stream):                                 # walks the stream BACKWARD
    state = int("".join(stream[:16][::-1]), 2)
    for i in range(16, len(stream)):
        state = f_inverse(state)
        if not compute_output_bit(state, pred) == int(stream[i]):
            return None                                   # mismatch -> you lose
    state = f_inverse(state)
    return compute_output_bit(state, pred)                # one predicted bit
```

### Clues

> **Clue:** The seed is only `secrets.randbits(16)` — 65536 possibilities. Option 4 ("guess seed")
> gives the flag for the right value. The whole challenge is a 16-bit state-recovery.

> **Clue:** `compute_output_bit(state, pred)` is the **parity of `state & pred`**. Pick a one-hot
> predicate `pred = 2**i` and it returns exactly **bit `i`** of the state — a bit-extraction oracle.

> **Clue:** Option 3's `pprngc(pred, stream)` runs `f_inverse` *backward* over a stream you supply and
> returns the next bit *before* it. If you feed it the 16 states you can reach forward (option 2) plus
> the fixed 16-bit prefix (option 1) and a one-hot predicate, it hands back one **seed** bit per query.
> Sixteen queries → the whole seed.

Clue → hypothesis: chain `f` forward 15 times from the leaked `f(seed)` to get a run of known states;
build each query's bitstream from those states' bit `i` plus the fixed prefix; the oracle returns seed
bit `i`. Reassemble the 16 bits and guess the seed.

### Test the hypothesis

`compute_output_bit(state, 2**i)` is bit `i`, so the bitstream for predicate `2**i` is just
`"".join(bit_i(state) for state in states)`, reversed to match the service's `[::-1]` convention, with
the fixed prefix prepended. Option 3 has a 16-use cap — exactly 16 bits — and option 2 a 15-use cap,
giving 16 known states counting the first leak. The caps are sized precisely for this attack. We drive
the service as a **local** pwntools `process()`, never a remote host.

### Solve

`examples/ch06/solve_pprngc.py`

```python
import os
import re
import sys

from pwn import context, process

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "pprngc")
context.log_level = "error"


def output_bit(state, pred):
    return bin(state & pred).count("1") % 2


def main() -> None:
    conn = process([sys.executable, "pprngc.py"], cwd=CHALL)
    conn.recvline()
    first_state = int(conn.recvline().decode().split(" ")[-1])

    states = [first_state]                       # chain f() forward 15 times
    for _ in range(15):
        conn.sendlineafter(b"guess seed ", b"2")
        conn.sendlineafter(b"Gimme a number! ", str(states[-1]).encode())
        states.append(int(conn.recvline().decode().strip()))

    conn.sendlineafter(b"guess seed ", b"1")
    prefix = conn.recvline().decode().strip()[:16]

    preds = [2 ** i for i in range(16)]
    seed_bits = []
    for i in range(16):                          # one seed bit per oracle query
        bits = "".join(str(output_bit(s, preds[i])) for s in states)[::-1]
        stream = prefix + bits
        conn.sendlineafter(b"guess seed ", b"3")
        conn.sendlineafter(b"Gimme the bitstream you want to predict! ", stream.encode())
        conn.sendlineafter(b"Oh, can you also give a predicate with that? ", str(preds[i]).encode())
        seed_bits.append(conn.recvline().decode().strip())

    seed = int("".join(seed_bits[::-1]), 2)
    conn.sendlineafter(b"guess seed ", b"4")
    conn.sendlineafter(b"Well, let's see it! ", str(seed).encode())
    out = conn.recvall(timeout=3).decode(errors="replace")
    match = re.search(r"lactf\{[^}]*\}", out)
    print("recovered seed:", seed)
    print("FLAG:", match.group(0) if match else "not found")
```

```console
$ python examples/ch06/solve_pprngc.py
recovered seed: 59396
FLAG: lactf{we_love_blum-micali_generators_h1MNZuJSFjlAEwc1}
```

(The seed is ⚠ different every run — it is a fresh `secrets.randbits(16)` each time the process starts.)

### Why it worked / generalize

The generator was linear and invertible, and the service *handed us* two oracles: a bit-extractor
(parity with a one-hot predicate) and a backward predictor. Linearity plus an oracle lets you read the
state one bit at a time instead of brute-forcing it. Whenever a service runs its PRNG forward *and*
backward, or exposes a parity/predicate check, look for a query sequence that isolates one state bit per
call. And note the discipline: we ran the challenge as a **local process**, as the course's rules
require.

## Challenge walkthrough: encrypted-mail (NEEDS-ATTENTION)

> Challenge: **encrypted-mail** — DownUnderCTF 2023 by joseph.
> Source: `DownUnderCTF/Challenges_2023_Public@b48f83db29` (`crypto/encrypted-mail`).
> License: none (organizer-published for practice).

This one shows the *limit* of the offline untemper and why MT19937 recovery sometimes needs real linear
algebra. The ctfkit predictor — the hard, teachable core — is verified; the full protocol forgery is
**not** scripted here (it needs the live nsjail service as an oracle plus a GF(2) solve). We teach the
reasoning and show the organizer-published flag.

### Recon

```console
$ python challenges/fetch.py encrypted-mail
$ ls challenges/encrypted-mail/src
Dockerfile  bot_users.py  crypto.py  db.py  server.py  flag.txt
```

There is **no** `output.txt` with a run of PRNG outputs. The crypto is a Chaum–Pedersen-style
zero-knowledge auth (quoted for teaching):

```python
def generate_challenges(self, n=128):
    for _ in range(n):
        b = round(random.random())                 # ONE bit of MT output leaks
        r = random.getrandbits(p.bit_length())     # hidden behind a discrete log
        c = random.getrandbits(p.bit_length())
        c1 = pow(g, r, p)
        c2 = pow(g, c, p) if b == 0 else pow(self.y, r, p)
        challenges.append((int(c1), int(c2)))
```

### Clues

> **Clue:** The only directly observable MT output is `b = round(random.random())` — a **single bit**,
> and `random.random()` already burned **two** 32-bit state words to produce it. You cannot untemper a
> single bit.

> **Clue:** The `getrandbits` values `r`, `c` *are* full state words, but they are published only as
> `g^r mod p` — hidden behind a discrete log. They never leak in the clear.

> **Clue:** You register your own public key `y = g^x` for a **known** `x`. Then when `b == 1`,
> `c2 = y^r = g^{x*r}`, so you can *check* a guess of `r` against `c1 = g^r`. Each of the 128
> sub-challenges thus becomes a 1-bit constraint on the MT stream.

Clue → hypothesis: MT19937's output is a *linear* function of its 19937 state bits. Collect enough
single-bit constraints (from many rounds against the live oracle) and solve a **GF(2) linear system**
for the full state — then clone the generator, predict the admin bot's stream, and forge the admin's
`Send flag` signature.

### Test the hypothesis (what we can verify offline)

The reusable, verified piece is the MT19937 predictor itself. On the *solvable* full-output case
(624 consecutive `getrandbits(32)`), `ctfkit` recovers the state end-to-end — this is the engine the
full attack sits on top of:

`examples/ch06/solve_encrypted_mail.py` (the verified core)

```python
import random

from ctfkit.crypto import MT19937

KNOWN_FLAG = "DUCTF{wait_its_all_linear_algebra?...always_has_been}"   # organizer-published


def demonstrate_prediction() -> bool:
    """Observe 624 getrandbits(32), then predict the next 10 exactly."""
    random.seed()
    observed = [random.getrandbits(32) for _ in range(624)]
    predictor = MT19937.from_outputs(observed)
    expected = [random.getrandbits(32) for _ in range(10)]
    predicted = [predictor.next_u32() for _ in range(10)]
    ok = expected == predicted
    print("MT19937 state recovery:", "OK" if ok else "FAILED")
    return ok
```

```console
$ python examples/ch06/solve_encrypted_mail.py
MT19937 state recovery: OK
NEEDS-ATTENTION: full protocol forgery not automated.
Organizer-published flag: DUCTF{wait_its_all_linear_algebra?...always_has_been}
```

### What finishing it requires (NEEDS-ATTENTION)

- Run the shipped `src/server.py` locally under Docker (nsjail) bound to **127.0.0.1**, as a 1-bit
  oracle (register `y = g^x` for a known `x`, read each `b`).
- Build the **GF(2) linear system**: represent each MT output bit as a XOR of state bits (the
  organizer's `solve/mt-precompute.py` builds ~19968 basis `MT19937` objects, one per state bit, so each
  observed bit becomes one equation), then Gaussian-eliminate to recover the 19937-bit state. This is
  the full version of the LFSR GF(2) idea from earlier — same algebra, far bigger matrix.
- Clone the recovered generator, predict the admin bot's stream, forge the admin `Send flag`
  signature, and read `flag_haver`'s reply.

The flag the organizers published is `DUCTF{wait_its_all_linear_algebra?...always_has_been}` — the name
itself tells you the technique.

### Why it worked / generalize

Everything an MT19937 emits is linear over its state bits, so **any** function of its outputs — even a
single rounded bit — is a linear equation. Full 32-bit outputs give you 624 equations at once
(untempering); sparse 1-bit leaks give you one equation at a time, so you gather many and solve the
system. When an offline untemper doesn't fit (floats, rounding, truncation, discrete-log hiding),
reach for the GF(2) matrix formulation. "It's all linear algebra… always has been."

## Summary

- `random` is a Mersenne Twister: fast, reproducible, and **not** secret-safe. Secure randomness is
  `secrets` / `os.urandom`.
- A small seed is a small keyspace — brute it. An LCG falls to three outputs and one modular inverse. An
  LFSR leaks its state over GF(2) once you see as many bits as it is wide.
- MT19937's tempering is reversible: **untemper 624 outputs** to rebuild the state, then predict forever.
  `getrandbits(32)` leaks whole state words; `random.random()` burns two words to give a 53-bit float,
  so bit-leaks of it need a GF(2) solve instead.
- `ctfkit.crypto` now has `untemper`, `MT19937` (from outputs/seed, predict forward, `random()`), and
  `LFSR` (clock/bits/recover_state) — a pure-Python replacement for SageMath on these attacks.
- Meta-skill: linear generators and reversible mixing are predictable. Find the state leak (outputs,
  bits, or an oracle) and reconstruct it.

## Exercises

1. **Timestamp seed.** A token server did `random.seed(int(time.time()))` at some moment in a known
   10-minute window and printed `random.getrandbits(32)`. Given the printed value and the window,
   recover the exact seed.

   <details><summary>Solution</summary>

   ```python
   import random
   def recover(printed, start, end):
       for s in range(start, end + 1):
           random.seed(s)
           if random.getrandbits(32) == printed:
               return s
   # Brute every second in the window; 600 seeds is nothing.
   ```

   A time-based seed is just a small keyspace. Narrow the window from HTTP `Date` headers or file
   timestamps and brute it.
   </details>

2. **Clone `random` from tokens.** A service prints 624 hex tokens, each `random.getrandbits(32)`.
   Predict the next three tokens.

   <details><summary>Solution</summary>

   ```python
   from ctfkit.crypto import MT19937
   outs = [int(t, 16) for t in tokens]          # 624 observed 32-bit outputs
   mt = MT19937.from_outputs(outs)
   print([mt.next_u32() for _ in range(3)])
   ```

   Exactly the `mt_predict.py` attack: 624 full outputs rebuild the state.
   </details>

3. **64-bit outputs.** A service prints `random.getrandbits(64)` values. How many do you need to clone
   the generator, and how do you feed them to `MT19937.from_outputs`?

   <details><summary>Solution</summary>

   Each 64-bit value is **two** 32-bit outputs: the low 32 bits come first, then the high 32 bits
   (`getrandbits(64) = lo | (hi << 32)`). So 312 values give 624 words:

   ```python
   words = []
   for v in values[:312]:
       words.append(v & 0xFFFFFFFF)             # first draw (low)
       words.append(v >> 32)                    # second draw (high)
   mt = MT19937.from_outputs(words)
   ```

   Getting the word order right is the whole trick; reverse it and the state is garbage.
   </details>

4. **Stretch — LCG with unknown modulus.** You see six consecutive outputs of `x = (a*x + c) mod m` but
   know none of `a, c, m`. Recover all three.

   <details><summary>Solution</summary>

   Form differences `t_i = x_{i+1} - x_i`. Then `t_{i+1} = a*t_i (mod m)`, so each
   `u_i = t_{i+2}*t_i - t_{i+1}^2` is a multiple of `m`; `m = gcd(u_0, u_1, …)` (clean up small
   factors). With `m` known, recover `a = (x2 - x1) * (x1 - x0)^{-1} mod m` and `c = x1 - a*x0`, exactly
   as in `lcg.py`. Truncated-output LCGs (only high bits shown) are the harder, lattice-based cousin.
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-6--predicting-random-numbers)
