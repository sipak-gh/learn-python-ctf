# Chapter 1 — The CTF Mindset and Your Toolbox

This chapter sets up how you'll work: what a CTF is, the clue-driven method you'll use on every
challenge, the rules that keep you legal, and the project layout. You'll build the skeleton of
**`ctfkit`** (the toolkit you grow one module per chapter) and the challenge **fetcher**, then solve
your first challenge. Next: [Chapter 2](02-python-for-ctf-data.md).

## What a CTF is

A **Capture The Flag** (CTF) is a security puzzle competition. The usual format is **jeopardy**: a board
of point-scored challenges sorted by category. You download a file or connect to a service, find a hidden
string — the **flag** — and submit it for points.

A flag has a fixed shape, so you know when you've won: a tag, braces, and a body.

| Example flag | Event prefix |
|---|---|
| `DUCTF{python_warmup}` | DownUnderCTF |
| `ictf{G()@+3c\|!~}` | ImaginaryCTF |
| `lactf{b4by_h1t_m3_0ne_m0r3_t1m3}` | LA CTF |
| `HTB{...}` | HackTheBox |

The categories this course covers:

- **Encoding / scripting** — data hidden behind an encoding or a small script.
- **Crypto** — classical ciphers, XOR, RSA, weak randomness.
- **Reversing** — understanding compiled or obfuscated code (here, Python bytecode).
- **Pyjail** — escaping a restricted Python sandbox.
- **Web** — Flask, template injection, insecure deserialization.
- **Forensics** — files, packet captures, steganography.
- **Pwn** — memory-corruption bugs in binaries.

Recognizing a flag is routine enough to script. A regex for `PREFIX{...}` finds flags in any output.

`examples/ch01/find_flag.py`

```python
import re

# One or more letters/digits, then {...} with any non-brace, non-space bytes.
FLAG_RE = re.compile(rb"[A-Za-z0-9_]+\{[^}\s]*\}")

blob = b"""
log line 1: nothing here
debug: user=admin token=DUCTF{clu3s_l3ad_to_fl4gs}
log line 3: done
"""

for match in FLAG_RE.findall(blob):
    print("found:", match.decode())
```

```console
$ python examples/ch01/find_flag.py
found: DUCTF{clu3s_l3ad_to_fl4gs}
```

The regex runs on `bytes` (the `rb"..."` prefix) because challenge output is bytes. More on bytes vs str
in [Chapter 2](02-python-for-ctf-data.md).

## The clue-driven method

CTF challenges are *designed* to be solved. The author plants signals — a file header, an odd constant, a
tiny number range, a reused key — that point to one technique. This course is built on following those
clues. Every walkthrough uses the same six steps:

1. **Recon** — fetch the files, list them, run `file`, read the prompt. Look before you theorize.
2. **Clues** — note each signal and what it suggests. We mark these in the text:
   > **Clue:** a `#coding:` line at the top of a source file means the file is in a non-UTF-8 encoding.
3. **Hypothesis** — turn the clue into a guess: "the whole file is punycode-encoded."
4. **Test** — a small experiment to confirm or kill the guess. Dead ends are normal and teach you something.
5. **Solve** — write the script that produces the flag.
6. **Generalize** — name the bug class so you spot it faster next time.

The skill isn't memorizing tricks. It's reading a challenge, seeing which clue is lit, and knowing which
drawer of the toolbox to open.

## Legal and ethical scope — read this first

Security skills come with rules. This course is about **defensive understanding** of bug classes on
**consenting, self-hosted, retired targets**. The rules are non-negotiable:

- **Only solve what you're authorized to.** We use **only** retired, organizer-published challenges, each
  pinned to a commit and attributed (see [Appendix D](appendix-d-running-challenges.md)). Nothing live,
  nothing scraped.
- **Everything runs locally.** Every service is your own local Docker container or a local Python process.
  Every connection in our scripts targets **127.0.0.1** — your own machine. Never connect to, scan, or
  script against any live, remote, third-party, or competition server.
- **Respect each source's terms.** Platforms such as CryptoHack, OverTheWire, and active HackTheBox content
  are *further practice only*; never publish OverTheWire level passwords.
- These techniques are for learning, not for attacking systems you don't own or lack permission to test.

Keep this in mind throughout. The point is to understand how a bug works so you can recognize and fix it —
not to attack anyone.

## Your environment

You need three things. Installing them is **not** covered here (see the [README](README.md) for versions);
configuring the project is.

- **Python 3.10+.** Verified on 3.10 (Ubuntu 22.04 / WSL2). A few things are version-specific — notably
  `.pyc` bytecode in [Chapter 7](07-python-reversing.md) — so 3.10 is the reference.
- **A virtualenv** with pinned dependencies, so your tools match ours exactly.
- **Docker**, for the few challenges that run a local service.

### The project layout

```text
learn-python-ctf/
  README.md
  pyproject.toml            # makes ctfkit an installable package
  requirements.txt          # pinned tool versions
  ctfkit/                   # the toolkit you grow, one module per chapter
    __init__.py
  tests/                    # pytest suite for ctfkit
  examples/chNN/            # every example + our solve scripts, per chapter
  challenges/
    fetch.py                # pulls each challenge at a pinned commit
    challenges.toml         # the catalogue (where each challenge lives)
    <name>/                 # downloaded challenge files (gitignored)
  project/chNN/             # full snapshot of ctfkit at the end of chapter NN
```

Two directories need a note:

- **`challenges/<name>/` is gitignored.** We never commit challenge files (see "How challenges work"
  below); you fetch them on demand.
- **`project/chNN/` is a checkpoint** — the complete toolkit at the end of chapter *NN*. When your code
  misbehaves, `diff` against it: `diff -r ctfkit project/ch03/ctfkit`.

### Set up the virtualenv

A **virtualenv** is an isolated Python with its own packages, so this project's pinned versions don't
collide with anything else on your machine.

```console
$ python3 -m venv .venv
$ . .venv/bin/activate
$ pip install -r requirements.txt
$ pip install -e .
```

`requirements.txt` pins the exact versions we verified:

```text
pwntools==4.15.0
pycryptodome==4.2.0
requests==2.34.2
scapy==2.8.0
Pillow==12.3.0
numpy==2.2.6
scipy==1.15.3
sympy==1.14.0
pyzbar==0.1.9
decompyle3==3.9.3
pytest==8.4.2
tomli==2.5.0
```

`pip install -e .` installs `ctfkit` in **editable** mode: the package points at your source tree, so edits
take effect immediately — no reinstall. That's what lets you grow `ctfkit` chapter by chapter and import
it from any solve script.

> A few challenges need extra packages you install only when you reach them — `flask` for
> [Chapter 9](09-web.md), and the system library `libzbar0` for `pyzbar`. We call these out in place.
> SageMath is **not** required; where an organizer's solution used Sage, we use a pure-Python equivalent.

## How challenges work: fetch, don't commit

The challenge archives are authoritative but mostly **unlicensed** — organizers published them for
practice, not redistribution. So we never copy a challenge file into this repo. Instead, a small
**fetcher** pulls each challenge to your machine at an exact commit, and each walkthrough quotes only short
excerpts for teaching, with an attribution box.

You'll see this box before every challenge:

> **Challenge:** `pyny` — DownUnderCTF 2023 by hashkitten. Source:
> `DownUnderCTF/Challenges_2023_Public`@`b48f83db29` (`beginner/pyny`).
> License: none (organizer-published for practice).

The fetcher reads `challenges/challenges.toml`, a catalogue with one entry per challenge:

```toml
[pyny]
repo = "DownUnderCTF/Challenges_2023_Public"
commit = "b48f83db2984bc7fa2ec7879a32d7efb1be8d333"
path = "beginner/pyny"
category = "encoding"
difficulty = "very-easy"
needs_service = false
event = "DownUnderCTF 2023"
author = "DownUnderCTF organisers"
license = "no license; organizer-published for practice"
```

Pinning the `commit` makes the fetch **reproducible**: everyone downloads the exact bytes we verified.
`fetch.py` downloads the whole `path` subtree into `challenges/<name>/`. It's idempotent (re-runs skip
cached files) and tries the GitHub API and `raw.githubusercontent.com` first, falling back to a shallow
sparse `git` checkout at the same commit.

You run it once per challenge:

```console
$ python challenges/fetch.py pyny
fetching pyny  <-  DownUnderCTF/Challenges_2023_Public:beginner/pyny@b48f83db29
  [pyny] 6 file(s) under beginner/pyny (6 downloaded, 0 cached)
done: 1 challenge(s) in .../learn-python-ctf/challenges/<name>/
```

The full fetcher source and catalogue are in [Appendix D](appendix-d-running-challenges.md); the complete
file is in `project/ch01/challenges/`.

## Building ctfkit: the package skeleton

Your project starts as an installable but empty package. `ctfkit/__init__.py` carries a version and a
docstring previewing the modules you'll add.

`ctfkit/__init__.py`

```python
"""ctfkit -- a small, readable toolkit for solving CTF challenges.

The package grows one module per chapter of *Learn Python for CTFs*:

* ctfkit.encoding   -- hex / base64 / url / rot / xor byte wrangling (ch02)
* ctfkit.io         -- socket and pwntools service wrappers          (ch03)
* ctfkit.crypto     -- xor breaking, RSA helpers, PRNG recovery      (ch04-06)
* ctfkit.rev        -- .pyc / marshal / dis reversing helpers         (ch07)
* ctfkit.web        -- SSTI probes and pickle RCE builders            (ch08-09)
* ctfkit.forensics  -- file magic, LSB stego, pcap reassembly         (ch10)
* ctfkit.pwn        -- cyclic offsets, flat payloads, leak math       (ch11)
"""

__version__ = "0.12.0"
```

`pyproject.toml` declares the package so `pip install -e .` works. The key parts:

```toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "ctfkit"
version = "0.12.0"
requires-python = ">=3.10"

[tool.setuptools]
packages = ["ctfkit"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

### Checkpoint

With the venv active and `pip install -e .` done, confirm the import:

`examples/ch01/toolkit_smoke.py`

```python
import ctfkit

print("ctfkit version:", ctfkit.__version__)
print("package file:", ctfkit.__name__)
```

```console
$ python examples/ch01/toolkit_smoke.py
ctfkit version: 0.12.0
package file: ctfkit
```

No tests yet — the first module and its tests arrive in [Chapter 2](02-python-for-ctf-data.md). Running
`pytest` now reports nothing to do:

```console
$ pytest -q

no tests ran in 0.00s
```

The complete project at this point is in `project/ch01/`.

## Challenge walkthrough: pyny

> **Challenge:** `pyny` — DownUnderCTF 2023 by hashkitten. Source:
> `DownUnderCTF/Challenges_2023_Public`@`b48f83db29` (`beginner/pyny`).
> License: none (organizer-published for practice).

A tiny, static challenge that teaches the whole method: recon, one clue, one hypothesis, done.

### Recon

```console
$ python challenges/fetch.py pyny
$ ls challenges/pyny/src
pyny.py
$ file challenges/pyny/src/pyny.py
challenges/pyny/src/pyny.py: ASCII text
```

The prompt (`README.md`) is a nudge: *"I've never seen a Python program like this before."* Open the
file and you see why — it's valid ASCII, but not readable Python:

```python
#coding: punycode
def _(): pass
('Correct!' if ('Enter the flag: ') == 'DUCTF{%s}' % _.____ else 'Wrong!')-gdd7dd23l3by980a4baunja1d4...
```

### Clues

> **Clue:** the first line is `#coding: punycode`. Python reads this directive and decodes the *entire
> source file* with that codec before compiling it. Any registered codec is allowed — so the file isn't
> broken, it's **encoded**.

> **Clue:** the trailing gibberish (`-gdd7dd23l3by980a4b...`) is the punycode-encoded body. Punycode (from
> internationalized domain names, [RFC 3492](https://www.rfc-editor.org/rfc/rfc3492)) moves the non-ASCII
> code points to the end after a `-` separator — exactly the shape you see here.

The clue is the encoding itself: decode the file and you get the real program.

### Test the hypothesis

Python decodes punycode directly. The one catch (the challenge's `HINTS.md` spells it out): preserve the
leading newline, so strip only the `#coding: punycode` marker and decode the rest:

```python
>>> raw = open("challenges/pyny/src/pyny.py", "rb").read()
>>> print(raw.replace(b"#coding: punycode", b"").decode("punycode"))

def ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ(): pass
ᵖʳᵢⁿᵗ('Correct!' if ᵢⁿᵖᵘᵗ('Enter the flag: ') == 'DUCTF{%s}' % ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ.__ⁿªᵐᵉ__ else 'Wrong!')
```

Now it reads as Python, in fancy Unicode letters. The check is
`input(...) == 'DUCTF{%s}' % python_warmup.__name__`. Python **NFKC-normalizes** identifiers before
compiling, so `ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ` *is* the identifier `python_warmup`, and `.__name__` returns that plain
string. The flag is `DUCTF{python_warmup}` — no need to run anything.

### Solve

`examples/ch01/solve_pyny.py`

```python
import os
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "pyny", "src", "pyny.py")


def main() -> None:
    raw = open(CHALL, "rb").read()
    # The codec name is the clue; strip the marker and decode the body.
    source = raw.replace(b"#coding: punycode", b"").decode("punycode")
    print("decoded source:\n" + source + "\n")

    # The check is: input == 'DUCTF{%s}' % python_warmup.__name__
    # Python normalises identifiers with NFKC, so the fancy-Unicode name
    # becomes the plain ASCII the interpreter actually sees.
    fancy_name = "ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ"
    name = unicodedata.normalize("NFKC", fancy_name)
    flag = "DUCTF{%s}" % name
    print("FLAG:", flag)


if __name__ == "__main__":
    main()
```

```console
$ python examples/ch01/solve_pyny.py
decoded source:

def ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ(): pass
ᵖʳᵢⁿᵗ('Correct!' if ᵢⁿᵖᵘᵗ('Enter the flag: ') == 'DUCTF{%s}' % ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ.__ⁿªᵐᵉ__ else 'Wrong!')

FLAG: DUCTF{python_warmup}
```

### Why it worked / generalize

This is **source-encoding obfuscation**: the program is normal Python wearing a disguise. Two language
features made the disguise:

- A `#coding:` directive can name any codec, so the file's bytes aren't the program's text.
- Python normalizes Unicode identifiers (NFKC), so confusable letters collapse to ordinary names.

The lesson is the clue-reading: **when a file won't parse but `file` says it's text, suspect an
encoding.** You'll see this reflex again in [Chapter 2](02-python-for-ctf-data.md), where decoding *is* the
whole game.

## Summary

- A CTF flag has a fixed shape, `PREFIX{...}`; a regex finds it in any output.
- Every challenge is solved the same way: **recon → clues → hypothesis → test → solve → generalize.**
- Scope is non-negotiable: retired, organizer-published challenges only; everything local; `127.0.0.1` only.
- The project is a venv + an editable `ctfkit` package you grow per chapter, plus a fetcher that pulls each
  challenge at a pinned commit (never committed).
- `pyny` showed the method end to end: a `#coding:` clue meant the source was punycode-encoded, and the
  flag fell out of the decoded program.

## Exercises

1. **Flag regex.** Extend `find_flag.py` so it also matches flags whose body contains spaces or `}` is on a
   later line. Test it against `b"the flag is ictf{a b c}"`.

   <details><summary>Solution</summary>

   Allow spaces but still stop at the closing brace by excluding only `}`:

   ```python
   import re
   FLAG_RE = re.compile(rb"[A-Za-z0-9_]+\{[^}]*\}")
   print(FLAG_RE.findall(b"the flag is ictf{a b c}"))
   # [b'ictf{a b c}']
   ```
   </details>

2. **Another codec.** Python registers many codecs. Encode `DUCTF{codecs_everywhere}` with the `"punycode"`
   codec and confirm you can decode it back.

   <details><summary>Solution</summary>

   ```python
   s = "DUCTF{codecs_everywhere}"
   enc = s.encode("punycode")
   print(enc)                       # b'DUCTF{codecs_everywhere}-' (ASCII passes through, '-' appended)
   print(enc.decode("punycode"))    # DUCTF{codecs_everywhere}
   ```

   Pure-ASCII text punycodes to itself plus a trailing `-`; the trick in `pyny` was the non-ASCII body.
   </details>

3. **Read the catalogue.** Run `python challenges/fetch.py --list` and find three challenges in the
   `encoding` category. Which chapter do you expect to meet them in? (Check the [README](README.md) table.)

   <details><summary>Solution</summary>

   `--list` prints category, type, name, and difficulty for every entry. The `encoding` challenges include
   `pyny`, `welcome-to-ductf`, and `complementary` — the first lands here, the other two in
   [Chapter 2](02-python-for-ctf-data.md).
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-1--the-ctf-mindset-and-your-toolbox)
