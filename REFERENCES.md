# References

This file lists the sources behind the facts in this course: the Python language and standard-library
rules, the practitioner tools (pwntools, PyCryptodome, Scapy, Pillow, NumPy, SymPy), the RFCs, specs and
papers each technique rests on, the CTF methodology guides, and the retired, organizer-published
challenges the course solves. Use it to check a claim or to read further.

Each source has two links: **original** (the live page) and **archived** (a durable snapshot). For web
pages the archived link points at the Internet Archive's [Wayback Machine](https://web.archive.org/); for
source files and directories on GitHub it points at [Software Heritage](https://www.softwareheritage.org/)
via the `swh:1:dir:` identifier (the git tree hash) of that directory at the pinned commit. Challenge
links point at the exact commit each challenge was fetched at (see Appendix D for the full attribution and
licensing notes). Program output shown in the chapters comes from running the course's own code on
Python 3.10 and isn't listed here.

## Primary references

Bookmark these; most entries below point into them.

- **The Python Standard Library (3.10)** — The reference for every stdlib module the course leans on (`struct`, `base64`, `socket`, `random`, `marshal`, `dis`, `pickle`, and more). [original](https://docs.python.org/3.10/library/index.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/index.html)
- **pwntools documentation** — The exploitation toolkit behind `ctfkit.io` and `ctfkit.pwn`: tubes, `context`, packing, `ELF`, `ROP`, `cyclic`. [original](https://docs.pwntools.com/en/stable/) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/)
- **PyCryptodome documentation** — The crypto library used for RSA key parsing and AES in the crypto and reversing chapters. [original](https://pycryptodome.readthedocs.io/en/latest/) · [archived](https://web.archive.org/web/https://pycryptodome.readthedocs.io/en/latest/)
- **Scapy documentation** — Packet parsing and pcap handling used throughout the forensics chapter. [original](https://scapy.readthedocs.io/en/latest/) · [archived](https://web.archive.org/web/https://scapy.readthedocs.io/en/latest/)
- **RFC 8017 — PKCS #1 v2.2** — The RSA primitives (RSAEP/RSADP) and the e/d/φ relations the RSA chapter builds on. [original](https://www.rfc-editor.org/rfc/rfc8017) · [archived](https://web.archive.org/web/https://www.rfc-editor.org/rfc/rfc8017)
- **CTF101 — the CTF Handbook (OSIRIS Lab, NYU)** — A concise, category-by-category reference wiki; the methodology spine for the course. [original](https://ctf101.org/) · [archived](https://web.archive.org/web/https://ctf101.org/)
- **CTF Field Guide (Trail of Bits)** — A broad reversing/pwn/web methodology primer from a leading offensive-security firm. [original](https://trailofbits.github.io/ctf/) · [archived](https://web.archive.org/web/https://trailofbits.github.io/ctf/)

## Chapter 1 — The CTF Mindset and Your Toolbox

Chapter file: [01-getting-started.md](01-getting-started.md)

- **Python docs — `codecs`** — `str`/`bytes` encode/decode and the registry of codecs (incl. punycode/idna) behind confusable-source decoding. [original](https://docs.python.org/3.10/library/codecs.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/codecs.html)
- **Python docs — `unicodedata`** — Unicode database and normalization used to de-obfuscate homoglyph identifiers. [original](https://docs.python.org/3.10/library/unicodedata.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/unicodedata.html)
- **PEP 263 — Defining Python Source Code Encodings** — Why a `# coding:` declaration lets any registered codec decode a `.py` file (the `pyny` trick). [original](https://peps.python.org/pep-0263/) · [archived](https://web.archive.org/web/https://peps.python.org/pep-0263/)
- **RFC 3492 — Punycode** — Punycode places non-ASCII code points after a `-` delimiter — the shape of `pyny`'s body. [original](https://www.rfc-editor.org/rfc/rfc3492) · [archived](https://web.archive.org/web/https://www.rfc-editor.org/rfc/rfc3492)
- **Python Language Reference — Identifiers and keywords** — NFKC normalization of identifiers collapses confusable Unicode letters to plain names. [original](https://docs.python.org/3.10/reference/lexical_analysis.html#identifiers) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/reference/lexical_analysis.html#identifiers)
- **CTF101 — Introduction / Getting Started** — The ethics/scope framing: only solve what you are authorized to. [original](https://ctf101.org/intro/) · [archived](https://web.archive.org/web/https://ctf101.org/intro/)
- **pyny** — Chapter 1's challenge: a `.py` with a `# coding: punycode` header. DownUnderCTF 2023, `beginner/pyny`. [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/beginner/pyny) · [archived](https://archive.softwareheritage.org/swh:1:dir:7ab18f70867ff151e7eb8ce7089bc741fff57f5c;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/beginner/pyny)

## Chapter 2 — Python for CTF: Bytes, Numbers, and Encodings

Chapter file: [02-python-for-ctf-data.md](02-python-for-ctf-data.md)

- **Python docs — `base64`** — Base16 (hex), Base32, Base64 and the url-safe variants, with padding rules. [original](https://docs.python.org/3.10/library/base64.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/base64.html)
- **Python docs — `int.to_bytes` / `int.from_bytes`** — Framing flags as integers and back — the core bytes↔int conversion. [original](https://docs.python.org/3.10/library/stdtypes.html#int.to_bytes) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/stdtypes.html#int.to_bytes)
- **Python docs — `struct`** — Format chars and endianness for fixed-width binary fields. [original](https://docs.python.org/3.10/library/struct.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/struct.html)
- **SymPy docs — `ntheory` (`factorint`)** — Full integer factorization used to split `complementary`'s product. [original](https://docs.sympy.org/latest/modules/ntheory.html) · [archived](https://web.archive.org/web/https://docs.sympy.org/latest/modules/ntheory.html)
- **Python docs — `urllib.parse`** — `quote` / `unquote_to_bytes` percent-encoding of bytes. [original](https://docs.python.org/3.10/library/urllib.parse.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/urllib.parse.html)
- **Aussie++ — playground and source** — The joke esolang whose glyph flip-table and `GIMME`/`I RECKON` semantics `welcome-to-ductf` uses. [original](https://aussieplusplus.vercel.app/) · [archived](https://web.archive.org/web/https://aussieplusplus.vercel.app/)
- **welcome-to-ductf** — Upside-down esolang source; flag is plain string concatenation. DownUnderCTF 2023, `beginner/welcome-to-ductf`. [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/beginner/welcome-to-ductf) · [archived](https://archive.softwareheritage.org/swh:1:dir:e966d87ff2a3adb731a36faa2cda5cd3f2e75d9f;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/beginner/welcome-to-ductf)
- **complementary** — Splits the flag into two integers and prints their product — a factoring warm-up. DownUnderCTF 2023, `beginner/complementary`. [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/beginner/complementary) · [archived](https://archive.softwareheritage.org/swh:1:dir:3761cbb3c1c4014badd4311237732e259da5c10c;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/beginner/complementary)

## Chapter 3 — Talking to Services and Automating

Chapter file: [03-talking-to-services.md](03-talking-to-services.md)

- **Python docs — `socket`** — `connect`/`recv`/`sendall` behind the hand-rolled `Service` wrapper. [original](https://docs.python.org/3.10/library/socket.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/socket.html)
- **Python docs — `threading`** — Daemon worker threads for the self-contained local echo-server examples. [original](https://docs.python.org/3.10/library/threading.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/threading.html)
- **pwntools — tubes** — `remote()`/`process()`, `recvuntil`, `sendline`, `interactive` — the service-I/O layer. [original](https://docs.pwntools.com/en/stable/tubes.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/tubes.html)
- **Docker docs — networking / published ports** — Publishing a container port bound to 127.0.0.1 keeps a local challenge off the network. [original](https://docs.docker.com/engine/network/) · [archived](https://web.archive.org/web/https://docs.docker.com/engine/network/)
- **Python docs — `random`** — `seed`/`choices`/`getrandbits` internals behind the small-seed brute force. [original](https://docs.python.org/3.10/library/random.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/random.html)
- **randomly-chosen** — Server seeds `random` from a 0–1336 range; brute all seeds. DownUnderCTF 2023, `beginner/randomly-chosen`. [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/beginner/randomly-chosen) · [archived](https://archive.softwareheritage.org/swh:1:dir:ddec20698d45418f270dc0cc6898b9d04d77e819;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/beginner/randomly-chosen)

## Chapter 4 — Classical Ciphers and XOR

Chapter file: [04-classical-and-xor.md](04-classical-and-xor.md)

- **Python docs — Built-in Types (`bytes`, `bytearray`)** — Byte-sequence operations, `zip` and `bytearray` for the XOR break. [original](https://docs.python.org/3.10/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview)
- **The Cryptopals Crypto Challenges — Set 1** — Normalised-Hamming key-size detection and per-column single-byte XOR (`break_repeating_key_xor`). [original](https://cryptopals.com/sets/1) · [archived](https://web.archive.org/web/https://cryptopals.com/sets/1)
- **greek-cipher** — Monoalphabetic substitution with Greek letters; crib from the flag format. LA CTF 2023, `2023/crypto/greek-cipher` (MIT). [original](https://github.com/uclaacm/lactf-archive/tree/3379d4a7b36680764a34e7dc817cc3c94c244764/2023/crypto/greek-cipher) · [archived](https://archive.softwareheritage.org/swh:1:dir:67f0584b1f7ca8f8be0a3c0029fa54f155332415;origin=https://github.com/uclaacm/lactf-archive;path=/2023/crypto/greek-cipher)
- **one-more-time-pad** — Repeating-key XOR where the key is the flag; known-plaintext recovery. LA CTF 2023, `2023/crypto/one-more-time-pad` (MIT). [original](https://github.com/uclaacm/lactf-archive/tree/3379d4a7b36680764a34e7dc817cc3c94c244764/2023/crypto/one-more-time-pad) · [archived](https://archive.softwareheritage.org/swh:1:dir:c97f03df7f8b2b9b7b939fe790f0eeb28fdfa642;origin=https://github.com/uclaacm/lactf-archive;path=/2023/crypto/one-more-time-pad)

## Chapter 5 — RSA from Scratch and Classic Attacks

Chapter file: [05-rsa.md](05-rsa.md)

- **Python docs — Built-in Functions: `pow`** — Three-argument `pow(c, d, n)` modular exponentiation (and `pow(a,-1,m)` inverse, 3.8+). [original](https://docs.python.org/3.10/library/functions.html#pow) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/functions.html#pow)
- **Python docs — `math.isqrt`** — Integer square root for Fermat factoring and integer roots. [original](https://docs.python.org/3.10/library/math.html#math.isqrt) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/math.html#math.isqrt)
- **PyCryptodome — RSA / `Crypto.PublicKey`** — Importing/parsing PEM keys and the number helpers. [original](https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html) · [archived](https://web.archive.org/web/https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html)
- **RFC 8017 — PKCS #1 v2.2** — The RSA primitives (RSAEP/RSADP) and the e/d/φ relations. [original](https://www.rfc-editor.org/rfc/rfc8017) · [archived](https://web.archive.org/web/https://www.rfc-editor.org/rfc/rfc8017)
- **rsa** — You are handed the private key — a PEM-parsing warm-up. ImaginaryCTF 2023, `Crypto/rsa`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e/Crypto/rsa) · [archived](https://archive.softwareheritage.org/swh:1:dir:f708d21d3e3c077066d20f6abfef98cd73ab650a;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges;path=/Crypto/rsa)
- **primary-knowledge** — Modulus `n` is prime, so φ(n)=n−1 and no factoring is needed. HTB Cyber Apocalypse 2024, `crypto/[Very Easy] Primary Knowledge`. [original](https://github.com/hackthebox/cyber-apocalypse-2024/tree/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/crypto/%5BVery%20Easy%5D%20Primary%20Knowledge) · [archived](https://archive.softwareheritage.org/swh:1:dir:5df678de56953ee681640e07f6b16f5c1fdfc243;origin=https://github.com/hackthebox/cyber-apocalypse-2024;path=/crypto/%5BVery%20Easy%5D%20Primary%20Knowledge)
- **apbq-rsa-i** — Two linear `a·p + b·q` hints recover `p,q`. DownUnderCTF 2023, `crypto/apbq-rsa-i`. [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/crypto/apbq-rsa-i) · [archived](https://archive.softwareheritage.org/swh:1:dir:37c7418922c4a7c07c52cdb53102ec5f658f5b87;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/crypto/apbq-rsa-i)

## Chapter 6 — Predicting "Random" Numbers

Chapter file: [06-attacking-randomness.md](06-attacking-randomness.md)

- **Python docs — `random` (Mersenne Twister notes)** — MT19937 is CPython's core generator; 624-word state and tempering. [original](https://docs.python.org/3.10/library/random.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/random.html)
- **Matsumoto & Nishimura, "Mersenne Twister" (ACM TOMACS 1998)** — The MT19937 definition and tempering transform — the origin of `untemper`. (ACM may block automated access; the DOI resolves in a browser.) [original](https://dl.acm.org/doi/10.1145/272991.272995) · [archived](https://web.archive.org/web/https://dl.acm.org/doi/10.1145/272991.272995)
- **pprngc** — Interactive LFSR-style PRNG; recover state over GF(2) and predict. LA CTF 2024, `2024/crypto/pprngc` (MIT). [original](https://github.com/uclaacm/lactf-archive/tree/3379d4a7b36680764a34e7dc817cc3c94c244764/2024/crypto/pprngc) · [archived](https://archive.softwareheritage.org/swh:1:dir:792db21a03e1e77ef404fdb6d6701c53a2d3efc9;origin=https://github.com/uclaacm/lactf-archive;path=/2024/crypto/pprngc)
- **encrypted-mail** — Leaks 624 `random.random()` outputs → full MT19937 state recovery. DownUnderCTF 2023, `crypto/encrypted-mail`. [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/crypto/encrypted-mail) · [archived](https://archive.softwareheritage.org/swh:1:dir:df2963615949e680c6b8b927d8b5269ddb614f24;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/crypto/encrypted-mail)

## Chapter 7 — Reversing Python: Bytecode, `.pyc`, and Obfuscation

Chapter file: [07-python-reversing.md](07-python-reversing.md)

- **Python docs — `marshal`** — The serialization format for code objects used when lifting constants from a `.pyc`. [original](https://docs.python.org/3.10/library/marshal.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/marshal.html)
- **Python docs — `dis`** — Disassembling recovered code objects. [original](https://docs.python.org/3.10/library/dis.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/dis.html)
- **Python docs — `importlib` (pyc header / `cache_from_source`)** — `MAGIC_NUMBER` and the 16-byte `.pyc` header layout (3.7+). [original](https://docs.python.org/3.10/library/importlib.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/importlib.html)
- **PEP 552 — Deterministic pycs** — Hash-based vs timestamp-based `.pyc` header flags. [original](https://peps.python.org/pep-0552/) · [archived](https://web.archive.org/web/https://peps.python.org/pep-0552/)
- **decompyle3 — Python bytecode decompiler** — Supports up to 3.8/3.9 and refuses 3.10 bytecode — so read `dis` output instead. [original](https://github.com/rocky/python-decompile3) · [archived](https://web.archive.org/web/https://github.com/rocky/python-decompile3)
- **PyCryptodome — `Crypto.Cipher` (AES)** — AES-CBC decryption of constants (`FLAG_ENC`/`KEY`/`IV`) lifted from bytecode. [original](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html) · [archived](https://web.archive.org/web/https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html)
- **impossible** — A shipped `__pycache__/*.cpython-310.pyc` leaks a module; `dis`/decompile it. DownUnderCTF 2023, `misc/impossible` (needs Python 3.10). [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/misc/impossible) · [archived](https://archive.softwareheritage.org/swh:1:dir:25ed0185accb9eaf1053372de4c52d6a1f21f7da;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/misc/impossible)
- **goated** — A check function Church-encoded into nested lambdas. ImaginaryCTF 2023, `Reversing/goated`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e/Reversing/goated) · [archived](https://archive.softwareheritage.org/swh:1:dir:6c54d856dc05e7a5e0398123e154a21b56ae29df;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges;path=/Reversing/goated)
- **snailchecker** — Mixed C/Python validator — the real logic is in the compiled component. ImaginaryCTF 2023, `Reversing/snailchecker`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e/Reversing/snailchecker) · [archived](https://archive.softwareheritage.org/swh:1:dir:691d7e5e44d55ec613826bcc880ad59b6e8d1a5b;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges;path=/Reversing/snailchecker)

## Chapter 8 — Pyjails: Escaping Python Sandboxes

Chapter file: [08-pyjail.md](08-pyjail.md)

- **Python docs — `pickle`** — Opcodes, `__reduce__`, protocol-4 `STACK_GLOBAL`/`EXT` and the security warning. [original](https://docs.python.org/3.10/library/pickle.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/pickle.html)
- **Python docs — `copyreg`** — The registry (`_inverted_registry`) used by pickle `EXT` opcodes. [original](https://docs.python.org/3.10/library/copyreg.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/copyreg.html)
- **Python docs — `pickletools`** — `pickletools.dis` for human-readable opcode disassembly of a pickle stream. [original](https://docs.python.org/3.10/library/pickletools.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/pickletools.html)
- **Python docs — `pydoc`** — `help()`/pydoc pager behavior behind the `helpless` `less` escape. [original](https://docs.python.org/3.10/library/pydoc.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/pydoc.html)
- **pydash — PyPI project page** — `set_`/`get` deep-path traversal and the restricted-key guard (6.0.0) for the `get_and_set` gadget. [original](https://pypi.org/project/pydash/) · [archived](https://web.archive.org/web/https://pypi.org/project/pydash/)
- **helpless** — The whole jail is `help()`'s pager; escape via `less`. DownUnderCTF 2023, `beginner/helpless` (SSH). [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/beginner/helpless) · [archived](https://archive.softwareheritage.org/swh:1:dir:7bdf6f944ac1d7f723d620a6687c0014f38029c6;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/beginner/helpless)
- **pycrib** — Blacklist-based restricted shell; reconstruct banned names dynamically. ImaginaryCTF 2022, `Misc/pycrib`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges/tree/ac2f0aa796a651e0eb730db12c3550e4470d4e9c/Misc/pycrib) · [archived](https://archive.softwareheritage.org/swh:1:dir:27ce6bdbdad0154f74b2a79728c65e0dd92ff97f;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges;path=/Misc/pycrib)
- **get_and_set** — Only `getattr`/`setattr` primitives — walk the object graph to builtins. ImaginaryCTF 2023, `Misc/get_and_set`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e/Misc/get_and_set) · [archived](https://archive.softwareheritage.org/swh:1:dir:99e64180770f938bf016769879717ffe92901814;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges;path=/Misc/get_and_set)
- **you_shall_not_call** — A custom `SecureUnpickler` opcode allow-list; craft a pickle around it. ImaginaryCTF 2023, `Misc/you_shall_not_call`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e/Misc/you_shall_not_call) · [archived](https://archive.softwareheritage.org/swh:1:dir:b324267b40a77d9b1b82808b1dd242874c2311fb;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges;path=/Misc/you_shall_not_call)
- **not-a-pyjail** — A "syntax checker" that can be tricked into executing. DownUnderCTF 2022, `misc/not-a-pyjail`. [original](https://github.com/DownUnderCTF/Challenges_2022_Public/tree/2213706f1a93120bd58b3e47076611d80341c76c/misc/not-a-pyjail) · [archived](https://archive.softwareheritage.org/swh:1:dir:21a1e395bb63dee3324c1e9232d867dccf61ab3e;origin=https://github.com/DownUnderCTF/Challenges_2022_Public;path=/misc/not-a-pyjail)

## Chapter 9 — Web: Flask, SSTI, and Pickle Deserialization

Chapter file: [09-web.md](09-web.md)

- **Jinja — Template Designer Documentation** — Template evaluation (SSTI) and the sandbox escapes used to reach RCE. [original](https://jinja.palletsprojects.com/en/3.1.x/templates/) · [archived](https://web.archive.org/web/https://jinja.palletsprojects.com/en/3.1.x/templates/)
- **Flask — `render_template_string`** — The SSTI sink. [original](https://flask.palletsprojects.com/en/3.0.x/api/#flask.render_template_string) · [archived](https://web.archive.org/web/https://flask.palletsprojects.com/en/3.0.x/api/#flask.render_template_string)
- **Requests — Quickstart / Advanced Usage** — `Session` cookie persistence, `params=`, `cookies=`/`headers=` for driving the web challenges. [original](https://requests.readthedocs.io/en/latest/user/quickstart/) · [archived](https://web.archive.org/web/https://requests.readthedocs.io/en/latest/user/quickstart/)
- **parrot-the-emu** — `render_template_string(user_input)` with no sanitization — classic Jinja2 SSTI. DownUnderCTF 2024, `beginner/parrot-the-emu`. [original](https://github.com/DownUnderCTF/Challenges_2024_Public/tree/f2797a33d8f5851508f37e854afceedf85eee8a3/beginner/parrot-the-emu) · [archived](https://archive.softwareheritage.org/swh:1:dir:7ece983ae50a07536e88b460a5742dfcef365a6d;origin=https://github.com/DownUnderCTF/Challenges_2024_Public;path=/beginner/parrot-the-emu)
- **minigolf** — Jinja2 SSTI stepping stone for the blacklisted variant. ImaginaryCTF 2022, `Web/minigolf`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges/tree/ac2f0aa796a651e0eb730db12c3550e4470d4e9c/Web/minigolf) · [archived](https://archive.softwareheritage.org/swh:1:dir:c869c14fcca76c485d560b434db03c52b6699383;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges;path=/Web/minigolf)
- **sstigolf** — Blacklist-golf SSTI: bypass with `|attr()` and bracket-free constructs. ImaginaryCTF 2022, `Web/sstigolf`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges/tree/ac2f0aa796a651e0eb730db12c3550e4470d4e9c/Web/sstigolf) · [archived](https://archive.softwareheritage.org/swh:1:dir:04b297b835b98cadc7f5b058b0c095892ed93e11;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges;path=/Web/sstigolf)
- **were-pickle-phreaks** — Pickle deserialization behind an import allow-list, over HTTP. HTB Cyber Apocalypse 2024, `misc/[Easy] Were Pickle Phreaks`. [original](https://github.com/hackthebox/cyber-apocalypse-2024/tree/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/misc/%5BEasy%5D%20Were%20Pickle%20Phreaks) · [archived](https://archive.softwareheritage.org/swh:1:dir:e33e88f0239cae5156f93fa3b774fcf8616ab0d2;origin=https://github.com/hackthebox/cyber-apocalypse-2024;path=/misc/%5BEasy%5D%20Were%20Pickle%20Phreaks)

## Chapter 10 — Forensics: File Formats, PCAPs, and Stego

Chapter file: [10-forensics.md](10-forensics.md)

- **Pillow — Image module** — PNG pixel access for the custom LSB-stego diff. [original](https://pillow.readthedocs.io/en/stable/reference/Image.html) · [archived](https://web.archive.org/web/https://pillow.readthedocs.io/en/stable/reference/Image.html)
- **NumPy — bitwise routines** — Array bit ops (`&1`, bit-packing) to vectorise LSB extract/embed across pixel planes. [original](https://numpy.org/doc/stable/reference/routines.bitwise.html) · [archived](https://web.archive.org/web/https://numpy.org/doc/stable/reference/routines.bitwise.html)
- **PNG (Portable Network Graphics) Specification, 3rd ed. (W3C)** — The PNG signature `89504e47` and length/type/CRC chunk layout (IHDR/IDAT/IEND) for carving and header repair. [original](https://www.w3.org/TR/png/) · [archived](https://web.archive.org/web/https://www.w3.org/TR/png/)
- **Scapy — usage / sessions** — `rdpcap` and TCP-session reassembly. [original](https://scapy.readthedocs.io/en/latest/usage.html) · [archived](https://web.archive.org/web/https://scapy.readthedocs.io/en/latest/usage.html)
- **Scapy — DNS/Raw layers API** — `Raw`/`DNSQR` parsing to carve HTTP beacons and DNS names offline. [original](https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html) · [archived](https://web.archive.org/web/https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html)
- **PCAP Capture File Format (IETF draft)** — The libpcap global-header magic `d4c3b2a1` and per-record `incl_len`/`orig_len`. [original](https://datatracker.ietf.org/doc/html/draft-gharris-opsawg-pcap) · [archived](https://web.archive.org/web/https://datatracker.ietf.org/doc/html/draft-gharris-opsawg-pcap)
- **RFC 6066 — TLS Extensions: Server Name Indication** — TLS SNI (`server_name`) used to attribute the encrypted flag-image transfer in the repaired pcap. [original](https://datatracker.ietf.org/doc/html/rfc6066) · [archived](https://web.archive.org/web/https://datatracker.ietf.org/doc/html/rfc6066)
- **pyzbar — PyPI project page** — QR/barcode decoding (forensics stretch) and the `libzbar0` runtime dependency. [original](https://pypi.org/project/pyzbar/) · [archived](https://web.archive.org/web/https://pypi.org/project/pyzbar/)
- **binwalk — firmware/file carving tool** — The signature-scan/auto-carve tool whose logic `sniff_magic` mirrors. [original](https://github.com/ReFirmLabs/binwalk) · [archived](https://web.archive.org/web/https://github.com/ReFirmLabs/binwalk)
- **steganographic** — Custom LSB stego; diff against `original.png` and invert `gen.py`. ImaginaryCTF 2023, `Forensics/steganographic`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e/Forensics/steganographic) · [archived](https://archive.softwareheritage.org/swh:1:dir:92d37378111ceab861230afa5053234abdd98a8b;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges;path=/Forensics/steganographic)
- **forensics** — A deliberately corrupted pcap; repair headers with `struct`. ImaginaryCTF 2023, `Forensics/forensics`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e/Forensics/forensics) · [archived](https://archive.softwareheritage.org/swh:1:dir:e023a674ba665dbb92e932f71d268a173db45797;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges;path=/Forensics/forensics)
- **whack-a-frog** — A pcap of the attack; reassemble streams with Scapy. corCTF 2022, `forensics/whack-a-frog` (AGPL-3.0). [original](https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/2eaff37d7337fcf6c8a221b415e2f6eed5fafafb/forensics/whack-a-frog) · [archived](https://archive.softwareheritage.org/swh:1:dir:a1e32350473edbc0f794232cce18c9cd60148507;origin=https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive;path=/forensics/whack-a-frog)

## Chapter 11 — Binary Exploitation with Python and pwntools

Chapter file: [11-pwn.md](11-pwn.md)

- **Python docs — `struct`** — `pack`/`unpack` for `p64`/`u64` leak math. [original](https://docs.python.org/3.10/library/struct.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/struct.html)
- **pwntools — ROP and ELF** — `ELF`, `context`, `ROP`, `cyclic`/`cyclic_find`. [original](https://docs.pwntools.com/en/stable/rop/rop.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/rop/rop.html)
- **pwntools — `fmtstr`** — `fmtstr_payload` automates the format-string write used in `form`. [original](https://docs.pwntools.com/en/stable/fmtstr.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/fmtstr.html)
- **System V Application Binary Interface — AMD64** — The x86-64 calling convention and 16-byte stack alignment at a call. [original](https://gitlab.com/x86-psABIs/x86-64-ABI) · [archived](https://web.archive.org/web/https://gitlab.com/x86-psABIs/x86-64-ABI)
- **Tool Interface Standard (TIS) ELF Specification v1.2** — ELF section/symbol structure behind pwntools' `ELF`. [original](https://refspecs.linuxfoundation.org/elf/elf.pdf) · [archived](https://web.archive.org/web/https://refspecs.linuxfoundation.org/elf/elf.pdf)
- **GDB — Examining Memory** — `x/gx` stack inspection and batch mode for the offset proof. [original](https://sourceware.org/gdb/current/onlinedocs/gdb/Memory.html) · [archived](https://web.archive.org/web/https://sourceware.org/gdb/current/onlinedocs/gdb/Memory.html)
- **ret2win** — Textbook `gets()` overflow; find the offset with `cyclic`. ImaginaryCTF 2023, `Pwn/ret2win`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e/Pwn/ret2win) · [archived](https://archive.softwareheritage.org/swh:1:dir:64d7ee5f545be58d9c4260a606871124037f1bab;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges;path=/Pwn/ret2win)
- **downunderflow** — Unsigned-short index underflow flips a privilege flag. DownUnderCTF 2023, `beginner/downunderflow`. [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/beginner/downunderflow) · [archived](https://archive.softwareheritage.org/swh:1:dir:c7518a2f6777ae0f3206f0bc4bce63b31c6c9b5c;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/beginner/downunderflow)
- **form** — `printf(buf)` format string; leak and write with `fmtstr_payload`. ImaginaryCTF 2023, `Pwn/form`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e/Pwn/form) · [archived](https://archive.softwareheritage.org/swh:1:dir:8efb1d65ab81e0f4163229f6d9ae35d819c1502c;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges;path=/Pwn/form)
- **one-byte** — A one-byte overflow redirects a return into `win()`. DownUnderCTF 2023, `beginner/one-byte`. [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/beginner/one-byte) · [archived](https://archive.softwareheritage.org/swh:1:dir:06aa5e2bb5a8a4923cfd71f6af5463fb5b71ceca;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/beginner/one-byte)
- **safe-calculator** — Off-by-one write plus an unused backdoor. DownUnderCTF 2023, `pwn/safe-calculator`. [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333/pwn/safe-calculator) · [archived](https://archive.softwareheritage.org/swh:1:dir:24f56c8594499d1b2e0625499c0746589f47f1d8;origin=https://github.com/DownUnderCTF/Challenges_2023_Public;path=/pwn/safe-calculator)
- **minimal** — Stripped binary with exact libc; leak and build a ret2libc/ROP chain. ImaginaryCTF 2023, `Pwn/minimal`. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e/Pwn/minimal) · [archived](https://archive.softwareheritage.org/swh:1:dir:c275da696fb05d47b0056c09a61338e5232cd5ff;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges;path=/Pwn/minimal)

## Chapter 12 — Putting It Together: Method, Writeups, and Where Next

Chapter file: [12-methodology-and-next.md](12-methodology-and-next.md)

- **CTF101 — the CTF Handbook** — General CTF categories, tooling, and beginner methodology. [original](https://ctf101.org/) · [archived](https://web.archive.org/web/https://ctf101.org/)
- **CTF Field Guide (Trail of Bits)** — Reversing/pwn/web methodology and exercises. [original](https://trailofbits.github.io/ctf/) · [archived](https://web.archive.org/web/https://trailofbits.github.io/ctf/)
- **picoCTF** — Beginner-friendly jeopardy practice with progressive difficulty. [original](https://picoctf.org/) · [archived](https://web.archive.org/web/https://picoctf.org/)
- **picoCTF Primer** — A beginner walkthrough of core CTF skills — a good companion for this course's audience. [original](https://primer.picoctf.org/) · [archived](https://web.archive.org/web/https://primer.picoctf.org/)
- **pwn.college** — Free interactive binary-exploitation / kernel curriculum. [original](https://pwn.college/) · [archived](https://web.archive.org/web/https://pwn.college/)
- **CryptoHack** — A guided cryptography challenge platform for crypto practice. [original](https://cryptohack.org/) · [archived](https://web.archive.org/web/https://cryptohack.org/)
- **OverTheWire — Wargames** — Linux/networking wargames for shell and recon fundamentals (never publish level passwords). [original](https://overthewire.org/wargames/) · [archived](https://web.archive.org/web/https://overthewire.org/wargames/)
- **Hack The Box** — An ongoing machines/challenges platform for continued practice. [original](https://www.hackthebox.com/) · [archived](https://web.archive.org/web/https://www.hackthebox.com/)

## Appendix A — Python-for-CTF Cheat Sheet

Chapter file: [appendix-a-python-ctf-cheatsheet.md](appendix-a-python-ctf-cheatsheet.md)

- **Python docs — `base64`** — Base64/Base16/Base32 encode-decode behaviour and padding rules. [original](https://docs.python.org/3.10/library/base64.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/base64.html)
- **Python docs — `struct`** — Format chars, endianness, `calcsize`/`pack`/`unpack`. [original](https://docs.python.org/3.10/library/struct.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/struct.html)
- **Python docs — `itertools`** — `product`/`permutations`/`combinations`/`cycle`/`count`/`islice` for brute force. [original](https://docs.python.org/3.10/library/itertools.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/itertools.html)
- **Python docs — `subprocess`** — `run`/`check_output`, stdin, text mode, and the shell-injection caveat. [original](https://docs.python.org/3.10/library/subprocess.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/subprocess.html)
- **Python docs — Built-in Functions: `pow`** — `pow(a,-1,m)` modular inverse and three-argument `pow` (3.8+). [original](https://docs.python.org/3.10/library/functions.html#pow) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/functions.html#pow)
- **Python docs — Built-in Types / `codecs`** — `int.from_bytes`/`to_bytes`, `bytes.hex`/`fromhex`, and `codecs` rot13/hex. [original](https://docs.python.org/3.10/library/stdtypes.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/stdtypes.html)

## Appendix B — pwntools Quick Reference

Chapter file: [appendix-b-pwntools-reference.md](appendix-b-pwntools-reference.md)

- **pwntools — tubes** — `process`/`remote`, `recvuntil`/`sendlineafter`/`interactive`. [original](https://docs.pwntools.com/en/stable/tubes.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/tubes.html)
- **pwntools — context** — `arch`/`bits`/`endian`/`log_level`/`binary` defaults. [original](https://docs.pwntools.com/en/stable/context.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/context.html)
- **pwntools — util.packing / util.fiddling** — `p8`/`p16`/`p32`/`p64`, `pack`/`unpack`, `flat`/`fit`. [original](https://docs.pwntools.com/en/stable/util/packing.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/util/packing.html)
- **pwntools — elf** — ELF symbols/GOT/PLT/search and `checksec` mitigations. [original](https://docs.pwntools.com/en/stable/elf/elf.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/elf/elf.html)
- **pwntools — rop** — ROP chain building, `find_gadget`, `call`/`raw`. [original](https://docs.pwntools.com/en/stable/rop/rop.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/rop/rop.html)
- **pwntools — util.cyclic** — `cyclic`/`cyclic_find` de Bruijn offset finding. [original](https://docs.pwntools.com/en/stable/util/cyclic.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/util/cyclic.html)
- **pwntools — gdb** — `gdb.attach`/`gdb.debug` and `context.terminal`. [original](https://docs.pwntools.com/en/stable/gdb.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/gdb.html)

## Appendix C — `ctfkit` API Reference

Chapter file: [appendix-c-ctfkit-reference.md](appendix-c-ctfkit-reference.md)

- **Python docs — `struct`** — The packing behaviour `ctfkit.pwn` wraps. [original](https://docs.python.org/3.10/library/struct.html) · [archived](https://web.archive.org/web/https://docs.python.org/3.10/library/struct.html)
- **pwntools — tubes** — The tube API `ctfkit.io` wraps. [original](https://docs.pwntools.com/en/stable/tubes.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/tubes.html)
- **pwntools — util.cyclic** — The cyclic/offset helpers `ctfkit.pwn` wraps. [original](https://docs.pwntools.com/en/stable/util/cyclic.html) · [archived](https://web.archive.org/web/https://docs.pwntools.com/en/stable/util/cyclic.html)

## Appendix D — Fetching and Running Challenges Locally

Chapter file: [appendix-d-running-challenges.md](appendix-d-running-challenges.md)

These are the mechanics of the pinned fetcher plus the full attribution for every challenge repository.
Each repo is linked at the exact commit the course fetches, with its Software Heritage directory snapshot
and its license status (see `CTF-RESEARCH.md` for the licensing analysis).

- **GitHub Docs — viewing/raw file access** — The `raw.githubusercontent.com/<repo>/<commit>/<path>` form the fetcher uses for pinned downloads. [original](https://docs.github.com/en/repositories/working-with-files/using-files/viewing-a-file) · [archived](https://web.archive.org/web/https://docs.github.com/en/repositories/working-with-files/using-files/viewing-a-file)
- **Git docs — `git-sparse-checkout`** — Sparse-checkout + partial clone (`--filter=blob:none`) for the subtree-fetch fallback. [original](https://git-scm.com/docs/git-sparse-checkout) · [archived](https://web.archive.org/web/https://git-scm.com/docs/git-sparse-checkout)
- **SageMath project site** — Optional dependency; the course's pure-Python MT19937 untempering replaces it where possible. [original](https://www.sagemath.org/) · [archived](https://web.archive.org/web/https://www.sagemath.org/)
- **DownUnderCTF 2023 (Challenges_2023_Public)** — Primary source: `pyny`, `welcome-to-ductf`, `complementary`, `randomly-chosen`, `helpless`, `one-byte`, `downunderflow`, `apbq-rsa-i`, `encrypted-mail`, `impossible`, `safe-calculator`. No LICENSE file — organizer-published; attribute and link. [original](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/b48f83db2984bc7fa2ec7879a32d7efb1be8d333) · [archived](https://archive.softwareheritage.org/swh:1:dir:43ed37cbb25d6ea52f491e6c1e3cd01c87079b80;origin=https://github.com/DownUnderCTF/Challenges_2023_Public)
- **DownUnderCTF 2024 (Challenges_2024_Public)** — Source of `parrot-the-emu`. No LICENSE file — organizer-published; attribute and link. [original](https://github.com/DownUnderCTF/Challenges_2024_Public/tree/f2797a33d8f5851508f37e854afceedf85eee8a3) · [archived](https://archive.softwareheritage.org/swh:1:dir:f942a46edce766b28e54134593f1c86501386a80;origin=https://github.com/DownUnderCTF/Challenges_2024_Public)
- **DownUnderCTF 2022 (Challenges_2022_Public)** — Source of `not-a-pyjail`. No LICENSE file — organizer-published; attribute and link. [original](https://github.com/DownUnderCTF/Challenges_2022_Public/tree/2213706f1a93120bd58b3e47076611d80341c76c) · [archived](https://archive.softwareheritage.org/swh:1:dir:5ce1b9791c1d0b33da59af280735a0f2e4c50f18;origin=https://github.com/DownUnderCTF/Challenges_2022_Public)
- **ImaginaryCTF 2023 Challenges** — Source of `rsa`, `goated`, `snailchecker`, `get_and_set`, `you_shall_not_call`, `forensics`, `steganographic`, `ret2win`, `form`, `minimal`. No LICENSE file — organizer-published; attribute and link. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e) · [archived](https://archive.softwareheritage.org/swh:1:dir:7dfd383daa3b8cade48f99d014593e458cece986;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges)
- **ImaginaryCTF 2022 Challenges** — Source of `pycrib`, `minigolf`, `sstigolf`. No LICENSE file — organizer-published; attribute and link. [original](https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges/tree/ac2f0aa796a651e0eb730db12c3550e4470d4e9c) · [archived](https://archive.softwareheritage.org/swh:1:dir:ebb9a1e405b272c649912d8af3bc7837b01e8bf9;origin=https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges)
- **LA CTF archive (uclaacm/lactf-archive)** — Source of `greek-cipher`, `one-more-time-pad`, `pprngc`. **MIT** licensed (© 2024 ACM at UCLA). [original](https://github.com/uclaacm/lactf-archive/tree/3379d4a7b36680764a34e7dc817cc3c94c244764) · [archived](https://archive.softwareheritage.org/swh:1:dir:e134b00b0818eccb7279faa73884a6c98ec27750;origin=https://github.com/uclaacm/lactf-archive)
- **HTB Cyber Apocalypse 2024 (official write-ups)** — Source of `primary-knowledge`, `were-pickle-phreaks`. No LICENSE file; HTB-published official write-ups (source sometimes embedded in README). [original](https://github.com/hackthebox/cyber-apocalypse-2024/tree/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a) · [archived](https://archive.softwareheritage.org/swh:1:dir:8b75c4940ca76d060d8727988618ccdc5e670c0d;origin=https://github.com/hackthebox/cyber-apocalypse-2024)
- **corCTF 2022 public challenge archive** — Source of `whack-a-frog`. **AGPL-3.0** repo-wide. [original](https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/2eaff37d7337fcf6c8a221b415e2f6eed5fafafb) · [archived](https://archive.softwareheritage.org/swh:1:dir:832c4010347dafabcdf27c9010337a50b6a3cf46;origin=https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive)
