# Learn Python for CTFs

This course teaches practical Python for Capture-the-Flag competitions while you build one real
thing: **`ctfkit`**, a small, readable toolkit you grow one module per chapter and then use to solve
**real, retired CTF challenges** across all seven classic categories — encoding, service I/O, crypto,
reversing, pyjails, web, forensics, and binary exploitation.

Like *Go by Example*, every idea comes with a small program and its exact output. Like *The Rust
Programming Language*, the chapters are a narrative that explains *why* each technique works and adds
to the project. By the end you will have a reusable toolkit, a folder of verified solve scripts, and
the instinct for turning "here's a weird file / a service / a binary" into a flag.

## What you'll build

- **`ctfkit/`** — a dependency-light Python package: `encoding` (hex/base64/url/rot/xor),
  `io` (socket + pwntools service wrappers), `crypto` (XOR breaking, RSA helpers and attacks,
  MT19937 + LFSR recovery), `rev` (`.pyc`/marshal/`dis`), `web` (SSTI probes, pickle RCE builders),
  `forensics` (file-magic, LSB stego, pcap reassembly), and `pwn` (cyclic offsets, flat payloads,
  leak math). It ships with a `pytest` suite.
- **`examples/chNN/solve_*.py`** — our own, original solve scripts for the chapter's challenges, each
  using `ctfkit` and printing the real flag.
- **`challenges/fetch.py` + `challenges.toml`** — a pinned, idempotent fetcher that pulls each retired
  challenge to your machine at an exact commit.

## Requirements

- **Python 3.10+** and a terminal. Everything was verified on Python 3.10 (Ubuntu 22.04 / WSL2).
- **Docker**, for the handful of challenges that run a local service.
- A **virtualenv** with the pinned `requirements.txt` (pwntools, pycryptodome, requests, scapy,
  Pillow, numpy, scipy, sympy, pyzbar, decompyle3, pytest). SageMath is **not** required.
- Installation of Python, Docker, or system packages is **not** covered here. If `python3 --version`
  prints 3.10+ and `docker run --rm hello-world` works, you're ready. (`pyzbar` needs the system
  `libzbar0` package.)

Set up once:

```console
$ python3 -m venv .venv && . .venv/bin/activate
$ pip install -r requirements.txt && pip install -e .
$ pytest -q
```

## Legal & ethics — read this first

This course is about **defensive understanding** of bug classes on **consenting, self-hosted, retired
targets**. The rules are simple and non-negotiable:

- **Only solve what you are authorized to.** We use **only** retired, organizer-published challenges,
  each pinned to a commit and attributed (see Appendix D). Nothing live, nothing scraped.
- **Everything runs locally.** Every service is your own local Docker container or a local Python
  process, and every connection in our scripts targets **127.0.0.1** — your own machine. Never
  connect to, scan, or script against any live, remote, third-party, or competition server.
- **Respect each source's terms.** Platforms such as CryptoHack, OverTheWire, and active HackTheBox
  content are *further practice only*; never publish OverTheWire level passwords.
- These techniques are for learning, not for attacking systems you don't own or lack permission to
  test. Don't.

## How to use this course

- **Read in order.** Each chapter uses only what earlier chapters taught.
- **Build `ctfkit` as you go.** Each chapter adds the helpers its technique needs; `project/chNN/` is
  the complete toolkit at the end of chapter NN — compare when stuck (`diff -r ctfkit project/ch06/ctfkit`).
- **Fetch each challenge yourself.** `python challenges/fetch.py <name>` downloads it to
  `challenges/<name>/` (gitignored). We never ship challenge files; you pull them at their pinned commit.
- **Type the solves.** `examples/chNN/solve_<name>.py` is our verified solution — type it, run it, and
  watch the real flag appear. Commands appear as `$ command` with the output you should see.
- **Do the exercises** (stretch challenges) before opening the walkthroughs.

## Table of contents

| #  | Chapter | You'll learn | Challenges |
|----|---------|--------------|------------|
| 1  | [The CTF Mindset and Your Toolbox](01-getting-started.md) | Recon, the flag format, the toolkit/fetcher skeleton | pyny |
| 2  | [Python for CTF: Bytes, Numbers, and Encodings](02-python-for-ctf-data.md) | `bytes`/`int` framing, hex/base64/url/rot/xor, `ctfkit.encoding` | welcome-to-ductf, complementary |
| 3  | [Talking to Services and Automating](03-talking-to-services.md) | Raw sockets then pwntools tubes, local Docker services, `ctfkit.io` | randomly-chosen |
| 4  | [Classical Ciphers and XOR](04-classical-and-xor.md) | XOR, single-byte/repeating-key breaking, crib dragging, `ctfkit.crypto` | greek-cipher, one-more-time-pad |
| 5  | [RSA from Scratch and Classic Attacks](05-rsa.md) | Modular math, `pow(c,d,n)`, small-`e`, prime modulus, Fermat, linear hints | rsa, primary-knowledge, apbq-rsa-i |
| 6  | [Predicting "Random" Numbers](06-attacking-randomness.md) | MT19937 untempering (pure Python), LFSR recovery | pprngc, encrypted-mail |
| 7  | [Reversing Python: Bytecode, `.pyc`, and Obfuscation](07-python-reversing.md) | marshal/`.pyc` loading, `dis`, deobfuscation, `ctfkit.rev` | impossible, goated |
| 8  | [Pyjails: Escaping Python Sandboxes](08-pyjail.md) | `__reduce__` and opcode-level pickle, jail escapes, `ctfkit.web` (pickle) | you_shall_not_call, helpless, pycrib, get_and_set |
| 9  | [Web: Flask, SSTI, and Pickle Deserialization](09-web.md) | Jinja2 SSTI probes → RCE, pickle over HTTP, `ctfkit.web` (SSTI) | parrot-the-emu, minigolf, sstigolf, were-pickle-phreaks |
| 10 | [Forensics: File Formats, PCAPs, and Stego](10-forensics.md) | File-magic, LSB stego, pcap repair + reassembly, `ctfkit.forensics` | steganographic, forensics, whack-a-frog |
| 11 | [Binary Exploitation with Python and pwntools](11-pwn.md) | Stack, calling convention, `cyclic`, ret2win, format strings, ROP, `ctfkit.pwn` | ret2win, downunderflow, form, one-byte, safe-calculator, minimal |
| 12 | [Putting It Together: Method, Writeups, and Where Next](12-methodology-and-next.md) | Workflow, writeups, teamwork, legal/ethical practice, next steps | — |
| A  | [Python-for-CTF Cheat Sheet](appendix-a-python-ctf-cheatsheet.md) | bytes/int/encoding one-liners, `pow`, `struct`, subprocess | |
| B  | [pwntools Quick Reference](appendix-b-pwntools-reference.md) | tubes, context, packing, ELF/ROP, cyclic, `gdb.attach` | |
| C  | [`ctfkit` API Reference](appendix-c-ctfkit-reference.md) | every module/function, the chapter that added it, an example | |
| D  | [Fetching and Running Challenges Locally](appendix-d-running-challenges.md) | `fetch.py`, `challenges.toml`, Docker, optional SageMath, the challenge index with attribution + licenses | |

References: [REFERENCES.md](REFERENCES.md) lists the sources behind each chapter — the Python, pwntools,
PyCryptodome, scapy and Pillow docs, the RFCs/specs (PKCS#1, PNG, pcap, ELF, System V ABI), the MT19937
paper, the CTF methodology guides, and each challenge's source repository at its pinned commit.
