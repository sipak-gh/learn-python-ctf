# Chapter 7 — Reversing Python: Bytecode, `.pyc`, and Obfuscation

Reversing in a CTF means turning a program back into understanding. Python gives you a huge advantage
over C or assembly: the compiled form is *bytecode* for a documented virtual machine, and the
interpreter ships the tools to read it. This chapter disassembles functions, loads leaked `.pyc` files,
lifts secrets from the constant pool, and unpicks obfuscation like lambda-calculus checkers — then
packages the moves into `ctfkit.rev`. You built PRNG recovery in
[Chapter 6](06-attacking-randomness.md); next is [Chapter 8](08-pyjail.md), where reading bytecode pays
off again inside pyjails.

## How Python compiles: code objects

Python compiles each function, module, and `lambda` to a **code object** (`__code__`). The code object
holds the bytecode plus the tables the VM needs: constants (`co_consts`), referenced names (`co_names`),
and local variable names (`co_varnames`). You can read all of it without running anything — the core
reversing skill.

`examples/ch07/dis_basics.py`

```python
import dis


def check(pin):
    secret = "p1n_1s_1337"
    return pin == secret


code = check.__code__
print("co_consts:", code.co_consts)
print("co_names: ", code.co_names)
print("co_varnames:", code.co_varnames)
print("--- disassembly ---")
dis.dis(check)
```

```console
$ python examples/ch07/dis_basics.py
co_consts: (None, 'p1n_1s_1337')
co_names:  ()
co_varnames: ('pin', 'secret')
--- disassembly ---
 13           0 LOAD_CONST               1 ('p1n_1s_1337')
              2 STORE_FAST               1 (secret)

 14           4 LOAD_FAST                0 (pin)
              6 LOAD_FAST                1 (secret)
              8 COMPARE_OP               2 (==)
             10 RETURN_VALUE
```

The secret `p1n_1s_1337` is sitting in `co_consts`. A password check that compares against a literal
leaks the literal — you never need to brute force it. `dis` output reads top to bottom as a stack
machine: `LOAD_*` pushes, `STORE_*` pops into a slot, `COMPARE_OP` and `RETURN_VALUE` consume the stack.

> **Python-for-CTF idiom:** `co_consts` is a tuple of every literal a function uses, including nested
> code objects. Printing it is the fastest way to find hardcoded keys, flags, and comparison targets.

## marshal: how code objects are stored

A `.pyc` stores a code object with [`marshal`](https://docs.python.org/3/library/marshal.html),
CPython's internal serialiser. `marshal` is deliberately *not* stable across versions — which is
why a `.pyc` is tied to one interpreter. Within a version you can round-trip one: dump to
bytes, load back, inspect, and `exec`.

`examples/ch07/marshal_roundtrip.py`

```python
import marshal

src = "def greet(name):\n    return 'hello ' + name\n"
code = compile(src, "<demo>", "exec")

blob = marshal.dumps(code)            # bytes you could write into a .pyc body
print("marshalled bytes:", len(blob))

restored = marshal.loads(blob)        # same code object, no source needed
ns = {}
exec(restored, ns)                    # define greet() in ns
print(ns["greet"]("ctf"))
print("nested consts:", [c for c in restored.co_consts])
```

```console
$ python examples/ch07/marshal_roundtrip.py
marshalled bytes: 193
hello ctf
nested consts: [<code object greet at 0x…, file "<demo>", line 1>, 'greet', None]
```

The module's code object nests the `greet` function as another code object inside its `co_consts`.
Secrets hide in these nested objects, so any constant scanner has to recurse — we handle that in
`ctfkit.rev.walk_consts` below. (The address in `<code object …>` varies per run.)

## The `.pyc` header: why Python version matters

Since [PEP 552](https://docs.python.org/3/library/importlib.html#module-importlib.util) (Python 3.7+) a
`.pyc` is a **16-byte header** followed by the marshalled code object:

| bytes | meaning |
|-------|---------|
| 0–4   | magic number (interpreter version + `\r\n`) |
| 4–8   | bit field (bit 0 set → hash-based `.pyc`) |
| 8–16  | timestamp + source size, or an 8-byte source hash |

The magic number encodes the exact CPython version. Load a `.pyc` under the wrong interpreter and
`marshal` chokes — the usual reason a leaked `.pyc` "won't open". This is why the course pins **Python
3.10**: the `impossible` challenge ships a `cpython-310` `.pyc`.

`examples/ch07/pyc_header.py`

```python
import importlib.util
import struct

magic = importlib.util.MAGIC_NUMBER
print("this interpreter's magic:", magic.hex(), magic)

KNOWN = {
    b"\x6f\x0d": "3.10",
    b"\xa7\x0d": "3.11",
    b"\xcb\x0d": "3.12",
}
tag = KNOWN.get(magic[:2], "unknown")
print("decoded version:", tag)

header = magic + struct.pack("<I", 0) + struct.pack("<II", 0, 0)
print("header length:", len(header))
flags = struct.unpack_from("<I", header, 4)[0]
print("flags:", flags, "(bit0 set => hash-based)" if flags & 1 else "(timestamp-based)")
```

```console
$ python examples/ch07/pyc_header.py
this interpreter's magic: 6f0d0d0a b'o\r\r\n'
decoded version: 3.10
header length: 16
flags: 0 (timestamp-based)
```

To read a leaked `.pyc`, skip the 16-byte header and `marshal.loads` the rest. If the magic doesn't
match your interpreter, install or switch to the matching Python; there is no shortcut, because
`marshal`'s layout changed.

## Reading a `.pyc` with `ctfkit.rev`

Put the pieces together: skip the header, unmarshal, and scan the constants — often the entire solve, no
decompiler required.

`examples/ch07/read_pyc.py`

```python
import importlib.util
import marshal

from ctfkit.rev import disassemble, find_strings, load_pyc

SRC = (
    "KEY = 'sup3r_s3cr3t_k3y'\n"
    "def unlock(pin):\n"
    "    return 'FLAG{demo}' if pin == 1337 else 'nope'\n"
)
code = compile(SRC, "module.py", "exec")

pyc = importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal.dumps(code)

restored = load_pyc(pyc)
print("strings in the .pyc:", find_strings(restored))
print("--- disassembly (first lines) ---")
print("\n".join(disassemble(restored).splitlines()[:8]))
```

```console
$ python examples/ch07/read_pyc.py
strings in the .pyc: ['sup3r_s3cr3t_k3y', 'FLAG{demo}', 'nope', 'unlock']
--- disassembly (first lines) ---
  1           0 LOAD_CONST               0 ('sup3r_s3cr3t_k3y')
              2 STORE_NAME               0 (KEY)

  2           4 LOAD_CONST               1 (<code object unlock at 0x…, file "module.py", line 2>)
              6 LOAD_CONST               2 ('unlock')
              8 MAKE_FUNCTION            0
             10 STORE_NAME               1 (unlock)
             12 LOAD_CONST               3 (None)
```

`find_strings` recursed into the nested `unlock` code object and pulled `FLAG{demo}` out — the win.

### A note on decompilers

Tools like `decompyle3`, `uncompyle6`, and `pycdc` try to reconstruct *source* from bytecode. They are
great when they work, but they lag the latest CPython. `decompyle3` (in our `requirements.txt`) does not
support 3.10:

```console
$ decompyle3 secret.pyc
Unsupported Python version, 3.10, for decompilation
```

That is the rule, not the exception. When the decompiler can't handle your
version, drop to `dis` and the constant pool — they always work, because the interpreter that runs the
bytecode can always read it. Read `dis` directly; it never goes out of date.

## Obfuscation patterns

Obfuscators hide readable names. Two patterns cover most Python challenges.

**1. String/`getattr` mangling.** Dangerous names are assembled from pieces so the literal never
appears, then reached with `getattr`/`__import__`.

`examples/ch07/deobfuscate_getattr.py`

```python
import dis

parts = ["sy", "st", "em"]
mod = "".join([chr(c) for c in (111, 115)])   # "os"
attr = "".join(parts)                          # "system"
print("reconstructed module:", repr(mod))
print("reconstructed attr:  ", repr(attr))

src = "getattr(__import__(m), a)"
print("--- what the obfuscated expression compiles to ---")
dis.dis(compile(src, "<obf>", "eval"))
```

```console
$ python examples/ch07/deobfuscate_getattr.py
reconstructed module: 'os'
reconstructed attr:   'system'
--- what the obfuscated expression compiles to ---
  1           0 LOAD_NAME                0 (getattr)
              2 LOAD_NAME                1 (__import__)
              4 LOAD_NAME                2 (m)
              6 CALL_FUNCTION            1
              8 LOAD_NAME                3 (a)
             10 CALL_FUNCTION            2
             12 RETURN_VALUE
```

The defence is always the same: don't run it, *print* the reconstructed strings. You'll see the same
trick weaponised in [Chapter 8](08-pyjail.md) to dodge blacklists.

**2. Lambda calculus / Church encoding.** Some checkers are one giant nest of `lambda`s with no names or
strings at all. That is *lambda calculus*: numbers are **Church numerals** (a number `n` is "apply `f`
to `x`, `n` times"), booleans pick one of two arguments, and arithmetic is function composition.
Recognise the shapes and you can decode the constants back to integers instead of executing the
obfuscation.

`examples/ch07/church_numerals.py`

```python
ZERO = lambda f: lambda x: x
SUCC = lambda n: lambda f: lambda x: f(n(f)(x))


def church_to_int(n):
    return n(lambda k: k + 1)(0)


one = SUCC(ZERO)
two = SUCC(one)
three = SUCC(two)
print("church numerals:", [church_to_int(n) for n in (ZERO, one, two, three)])

TRUE = lambda a: lambda b: a
FALSE = lambda a: lambda b: b
print("TRUE  picks:", TRUE("yes")("no"))
print("FALSE picks:", FALSE("yes")("no"))

ADD = lambda m: lambda n: lambda f: lambda x: m(f)(n(f)(x))
print("1 + 2 =", church_to_int(ADD(one)(two)))
```

```console
$ python examples/ch07/church_numerals.py
church numerals: [0, 1, 2, 3]
TRUE  picks: yes
FALSE picks: no
1 + 2 = 3
```

`church_to_int` applies "increment" to `0` as many times as the numeral encodes, giving back an ordinary
integer. That one helper is enough to read the constants out of a lambda-calculus checker — exactly what
`goated` needs.

## Building ctfkit: `rev`

`ctfkit.rev` turns this chapter's moves into reusable helpers: the 3.10 magic, a header-length helper, a
marshal loader, a `.pyc` loader that fails loudly on a version mismatch, a disassembler returning a
string, and two constant scanners.

`project/ch07/ctfkit/rev.py` (new module — the key functions)

```python
PYC_MAGIC_3_10 = importlib.util.MAGIC_NUMBER


def load_pyc(data: bytes) -> CodeType:
    """Parse a ``.pyc``: skip the header, unmarshal the code object."""
    magic = data[:4]
    if magic != PYC_MAGIC_3_10:
        raise ValueError(
            f"magic {magic.hex()} != this interpreter's {PYC_MAGIC_3_10.hex()}; "
            "run under the matching Python version"
        )
    return marshal.loads(data[pyc_header_len(data):])


def walk_consts(code: CodeType):
    """Yield every constant in ``code`` and nested code objects, recursively."""
    for const in code.co_consts:
        yield const
        if isinstance(const, CodeType):
            yield from walk_consts(const)


def find_strings(code: CodeType) -> list[str]:
    """Collect all string constants (including nested functions)."""
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
```

`load_pyc` takes raw **bytes** — call it as `load_pyc(open(p, "rb").read())`. The loud `ValueError` on a
magic mismatch is deliberate: it tells you to switch interpreters instead of silently returning garbage.
`walk_consts` recurses so `find_strings` sees secrets buried in nested functions.

### Checkpoint

```console
$ cd project/ch07 && pytest -q
.....................                                                    [100%]
21 passed in 0.05s
```

The complete project at this point is in `project/ch07/`.

## Challenge walkthrough: impossible

> Challenge: **impossible** — DownUnderCTF 2023 by ghostccamm. Source:
> `DownUnderCTF/Challenges_2023_Public@b48f83db29` (`misc/impossible`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py impossible
$ ls challenges/impossible/publish/impossible/app/utils
__init__.py  __pycache__  crypto.py
$ ls challenges/impossible/publish/impossible/app/utils/__pycache__
__init__.cpython-310.pyc  crypto.cpython-310.pyc
$ file challenges/impossible/publish/impossible/app/utils/__pycache__/crypto.cpython-310.pyc
crypto.cpython-310.pyc: data
```

The prompt gloats that the challenge is unsolvable. The shipped `crypto.py` makes the same claim in a
comment:

```python
# i have changed them all on the challenge instance just to make sure it is impossible to solve
FLAG_ENC='5700668797b137bb540ff5c7febf0f48...'
KEY='8deee6793066fa6529a9af2ef31723ca...'
IV='104e20c2abf12b342fe27064cead0c4f'
```

### Clues

> **Clue:** the author left `utils/__pycache__/crypto.cpython-310.pyc` in the published files. CPython
> writes a `.pyc` the first time a module imports — unless `PYTHONDONTWRITEBYTECODE` is set or the cache
> is cleaned from the image. That cache was compiled from the *real* module that ran on the server.

> **Clue:** the source `FLAG_ENC`/`KEY`/`IV` are fakes ("changed on the instance"). The `.pyc` holds the
> true values in its constant pool — and the magic is `cpython-310`, so it loads cleanly under our pinned
> interpreter.

Clue → hypothesis: don't trust the `.py`; trust the compiled `.pyc`. Lift its hex constants and run the
AES-CBC decrypt the source describes.

### Test the hypothesis

Load the `.pyc` and scan for long hex strings:

```console
$ python -c "import sys; from ctfkit.rev import load_pyc, find_strings; \
code=load_pyc(open(sys.argv[1],'rb').read()); \
print([len(s) for s in find_strings(code) if all(c in '0123456789abcdef' for c in s) and len(s)>=32])" \
  challenges/impossible/publish/impossible/app/utils/__pycache__/crypto.cpython-310.pyc
[256, 64, 32]
```

Three constants — a 256-hex ciphertext, a 64-hex (32-byte) AES key, a 32-hex (16-byte) IV — and their
first bytes (`ed4e…`, `f122…`, `b9e3…`) differ from the fake source (`5700…`, `8dee…`, `104e…`). The
real values were in the cache all along.

### Solve

`examples/ch07/solve_impossible.py` loads the `.pyc` with `ctfkit.rev`, lifts the three hex constants in
source order, and decrypts:

```python
from ctfkit.rev import find_strings, load_pyc

code = load_pyc(open(PYC, "rb").read())
hexes = [s for s in find_strings(code)
         if len(s) >= 32 and all(c in "0123456789abcdef" for c in s)]
flag_enc, key, iv = (bytes.fromhex(hexes[0]),
                     bytes.fromhex(hexes[1]),
                     bytes.fromhex(hexes[2]))
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
flag = unpad(cipher.decrypt(flag_enc), 32)
print("FLAG:", flag.decode())
```

```console
$ python examples/ch07/solve_impossible.py
FLAG: Congrats! You solved this impossible challenge! Here is the flag: DUCTF{o0p5_i_f0rG0t_aBoUt_pYc4Ch3!!1!}
```

### Why it worked / generalize

The bug class is **trusting source over bytecode**. A shipped `__pycache__`, a leaked `.pyc` in a Docker
layer, or a `.pyc`-only distribution all carry the real logic and constants. Whenever you see a `.pyc`,
load it and scan `co_consts` before doing anything harder. Match the interpreter version to the magic
first.

## Challenge walkthrough: goated

> Challenge: **goated** — ImaginaryCTF 2023 by puzzler7. Source:
> `ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026` (`Reversing/goated`).
> License: none (organizer-published for practice). The flag is not in
> `ictf{}` form; wrap the recovered input yourself.

### Recon

```console
$ python challenges/fetch.py goated
$ ls challenges/goated/challenge
gen.py  goated.py  lambda_calc.py  x.py
$ wc -l challenges/goated/challenge/goated.py
0 challenges/goated/challenge/goated.py
$ wc -c challenges/goated/challenge/goated.py
165398 challenges/goated/challenge/goated.py
```

`goated.py` is 165 KB on a **single line** (zero newlines) — one enormous expression. The first
characters are all nested `lambda`s:

```python
print((((lambda ______:((lambda ___:______(lambda _:___(___)(_)))...
```

### Clues

> **Clue:** no names, no strings, nothing but `lambda f: lambda x: ...` shapes. That is lambda calculus
> / Church encoding, not ordinary obfuscation.

> **Clue:** the README says it "converts the user input to a list of bits, does a little bit of math on
> it, and compares it to a hardcoded list." A linear check over the input: `input * a + b == c`.

Clue → hypothesis: you don't have to *run* the lambdas, only *read their shape*. Peel the
matching-parenthesis groups to isolate the three Church numerals `a`, `b`, `c`, decode them to integers,
then recover `input = (c - b) // a` and turn it back into bytes.

### Test the hypothesis

The decode step reuses the Church-numeral idea from `church_numerals.py`. A Church list is decoded bit
by bit with `head`/`tail`/`isempty` combinators; the solve script carries small versions of them. The
giveaway that the hypothesis is right: `(c - b)` is **exactly divisible** by `a`, and the resulting
integer turns into all-printable bytes.

### Solve

`examples/ch07/solve_goated.py` strips the outer `print((` wrapper, splits the expression into its
parenthesised groups with a tiny matching-paren parser, `eval`s only the isolated Church numerals
(self-contained lambdas, no I/O), decodes them, and solves the linear equation:

```python
a, b, c = bdec(eval(a)), bdec(eval(b)), bdec(eval(c))
x = (c - b) // a
body = long_to_bytes(x).decode("latin-1")
print("recovered input:", body)
print("FLAG:", f"ictf{{{body}}}")
```

```console
$ python examples/ch07/solve_goated.py
recovered input: G()@+3c|!~
FLAG: ictf{G()@+3c|!~}
```

### Why it worked / generalize

The bug class is **symbolic recovery of an obfuscated check**. However scary the encoding looks, a
comparison `f(input) == constant` is only as strong as `f`. If `f` is linear (or otherwise invertible),
you recover the input algebraically — never brute forcing, never running the whole obfuscation. Read the
structure, find the equation, invert it.

## Summary

- Python compiles to bytecode in **code objects**; `dis`, `co_consts`, and
  `co_names` let you read logic and secrets without running anything.
- A `.pyc` is a 16-byte header plus a `marshal`-serialised code object. The
  **magic number ties it to one interpreter version** — match the version or
  `marshal` fails. This is why the course pins Python 3.10.
- A leaked `.pyc` usually *is* the solve: load it and scan the constant pool
  (`ctfkit.rev.load_pyc` + `find_strings`) for keys and flags.
- Decompilers lag CPython; when they can't handle your version, read `dis`
  output and constants directly — those never go stale.
- Obfuscation is about hidden names: reconstruct strings instead of running
  them, and recognise lambda-calculus/Church encoding to decode constants
  algebraically.

## Exercises

1. **Disassemble a comparison.** Write a function that checks a password
   against a literal, then recover the literal using only `__code__.co_consts`
   (no source). Confirm with `dis`.

   <details><summary>Solution</summary>

   ```python
   def login(p):
       return p == "letmein-2023"

   print([c for c in login.__code__.co_consts if isinstance(c, str)])
   # -> ['letmein-2023']
   ```

   The literal is in the constant pool; `dis.dis(login)` shows the matching
   `LOAD_CONST`.
   </details>

2. **Hand-build and read a `.pyc`.** Compile a module with a secret, prepend
   `importlib.util.MAGIC_NUMBER + b"\x00"*12`, then recover the secret with
   `ctfkit.rev.load_pyc` + `find_strings`. (See `examples/ch07/read_pyc.py`.)

   <details><summary>Solution</summary>

   Follow `read_pyc.py` exactly: the header is magic + 12 zero bytes, the body
   is `marshal.dumps(compile(src, "m.py", "exec"))`, and `find_strings`
   recurses into nested functions to return the secret.
   </details>

3. **Wrong-magic error.** Feed `ctfkit.rev.load_pyc` a blob whose first four
   bytes are zeros. What happens, and why is a loud failure the right design?

   <details><summary>Solution</summary>

   It raises `ValueError: magic 00000000 != this interpreter's 6f0d0d0a; run
   under the matching Python version`. A loud failure tells you to switch
   interpreters; silently returning garbage would send you chasing a
   non-existent bug.
   </details>

4. **Church numeral round-trip.** Using `examples/ch07/church_numerals.py`,
   build the numeral for `5` with `SUCC` and confirm `church_to_int` returns
   `5`. Then decode `ADD(two)(three)`.

   <details><summary>Solution</summary>

   ```python
   five = SUCC(SUCC(SUCC(SUCC(SUCC(ZERO)))))
   print(church_to_int(five))              # 5
   print(church_to_int(ADD(two)(three)))   # 5
   ```
   </details>

5. **Stretch — snailchecker.** `snailchecker` (ImaginaryCTF 2023) mixes a small
   C validator with a Python wrapper. Fetch it, identify which language holds
   the real check, and sketch how you'd bridge the two (reverse the compiled
   component, replicate it in Python). This is mixed-language reversing — the
   clue is that `check.py` is only glue.

   <details><summary>Solution sketch</summary>

   The Python `check.py` is a CLI shim; the real validation is in the compiled
   C component. Reverse it with `objdump`/Ghidra to recover the algorithm, then
   re-implement that algorithm in Python to produce the accepted input. No
   single `ctfkit` helper solves it — it is practice at recognising where the
   logic actually lives.
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-7--reversing-python-bytecode-pyc-and-obfuscation)
