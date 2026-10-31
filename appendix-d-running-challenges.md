# Appendix D — Fetching and Running Challenges Locally

This course never ships challenge files. The archives it draws on are
authoritative but mostly **unlicensed** — organisers published them for practice
after each event — so copying them into this repository would be wrong. Instead,
a small pinned fetcher pulls each challenge to *your* machine on demand, into a
git-ignored directory; the course ships only **our own** solve scripts and the
`ctfkit` package.

This appendix covers the fetcher (`challenges/fetch.py`), its manifest
(`challenges.toml`), how to run the few challenges that need a live service under
Docker, why SageMath is optional, and the full attributed challenge index. Read
the legal framing at the end — it is not optional.

## Legal & ethics (read first)

From the course's ground rules ([Chapter 1](01-getting-started.md), [README](README.md)):

- **Only solve what you are authorized to.** We use **only** retired, organiser-published challenges,
  each pinned to an exact commit and attributed in the index below. Nothing scraped, nothing live.
- **Everything runs locally.** Every service is your **own** local Docker container or Python process,
  and every `remote()`/connection in our scripts targets **127.0.0.1** — your machine. Never connect to,
  scan, or script against any live, remote, third-party, or competition server.
- **Respect each source's terms.** Platforms such as CryptoHack, OverTheWire, and *active* HackTheBox
  content are further-practice mentions only; never publish OverTheWire level passwords. The HTB entries
  used here come from the `cyber-apocalypse-2024` **official write-up repo**, which HackTheBox itself
  publishes after the event — referencing it is sanctioned by the organiser.
- **Defensive framing only.** These techniques are for understanding bug classes on consenting,
  self-hosted, retired targets. Not for attacking systems you do not own or lack permission to test.

Absence of a `LICENSE` file means default copyright (all rights reserved to the
authors). We therefore **attribute** each challenge and link to its source at a
pinned commit rather than redistributing it. Quote only short excerpts inline for
teaching. If you fork this course, keep it that way.

## The `challenges/` directory

Only three things in `challenges/` are committed; everything a fetch downloads is
ignored.

```text
challenges/
├── fetch.py          # the fetcher (committed)
├── challenges.toml   # the manifest / source of truth (committed)
├── .gitkeep          # keeps the empty dir in git (committed)
└── <name>/           # fetched at runtime — GITIGNORED, never committed
```

The relevant `.gitignore` lines:

```text
challenges/*
!challenges/fetch.py
!challenges/challenges.toml
!challenges/.gitkeep
```

So `python challenges/fetch.py pyny` creates `challenges/pyny/`, and git ignores
it. Delete `challenges/<name>/` any time and re-fetch — it is reproducible.

## `challenges.toml` — the manifest

One table per challenge records *where* it lives so the fetcher can pull it — the
single source of truth driving both `fetch.py` and this appendix. Each entry:

```ini
[pyny]
repo = "DownUnderCTF/Challenges_2023_Public"   # owner/name on GitHub
commit = "b48f83db2984bc7fa2ec7879a32d7efb1be8d333"  # pinned commit (reproducible)
path = "beginner/pyny"            # directory to download (whole subtree)
category = "encoding"             # drives --category and the index
difficulty = "very-easy"
needs_service = false             # true = needs Docker / a running server
event = "DownUnderCTF 2023"       # attribution
author = "DownUnderCTF organisers"
license = "no license; organizer-published for practice"
```

Pinning `commit` (not a branch) means you fetch exactly the files the solve
script was verified against, even if the upstream repo changes later.

## `fetch.py` — usage

```console
$ python challenges/fetch.py pyny rsa form   # specific challenges
$ python challenges/fetch.py --all           # everything in the manifest
$ python challenges/fetch.py --category crypto   # a whole category
$ python challenges/fetch.py --list          # show the catalogue and exit
$ python challenges/fetch.py --force pyny     # re-download cached files
```

By default files land next to the script, in `challenges/<name>/`. Override the
destination (handy for out-of-tree verification) with the `CTFKIT_FETCH_DEST`
environment variable.

`--list` groups the catalogue by category and marks which need a service:

```console
$ python challenges/fetch.py --list
  crypto    static   rsa                          very-easy
  crypto    static   greek-cipher                 easy
  ...
  pwn       service  ret2win                      easy
  ...
  web       service  parrot-the-emu               easy
```

Fetching is **idempotent** — a first run downloads, a second run is cached:

```console
$ python challenges/fetch.py pyny
fetching pyny  <-  DownUnderCTF/Challenges_2023_Public:beginner/pyny@b48f83db29
  [pyny] 6 file(s) under beginner/pyny (6 downloaded, 0 cached)
done: 1 challenge(s) in challenges/<name>/

$ python challenges/fetch.py pyny
fetching pyny  <-  DownUnderCTF/Challenges_2023_Public:beginner/pyny@b48f83db29
  [pyny] 6 file(s) under beginner/pyny (0 downloaded, 6 cached)
done: 1 challenge(s) in challenges/<name>/
```

```console
$ find challenges/pyny -type f | sort
challenges/pyny/HINTS.md
challenges/pyny/README.md
challenges/pyny/ctfcli.yaml
challenges/pyny/publish/pyny.py
challenges/pyny/solve/solver.py
challenges/pyny/src/pyny.py
```

### How it fetches

1. **Primary:** the GitHub git-tree API lists every file under `path` at the pinned `commit` (one call),
   then each file is pulled from `https://raw.githubusercontent.com/<repo>/<commit>/<path>`.
2. **Fallback:** if the API is unavailable, a shallow sparse `git` checkout of just `path` at that commit
   (`git clone --filter=blob:none --no-checkout` → `sparse-checkout set <path>` → `checkout <commit>`).

Both paths fetch exactly the pinned commit. Set a `GITHUB_TOKEN` environment
variable to lift the unauthenticated API rate limit if you fetch `--all`
repeatedly.

## Running a challenge

**Static challenges** (`needs_service = false`) are just files — fetch them and
run the solve script:

```console
$ python challenges/fetch.py pyny
$ python examples/ch01/solve_pyny.py
```

**Service challenges** (`needs_service = true`) need something listening locally.
In this course they take one of three shapes, always targeting **127.0.0.1 on
your own machine**:

- A local **binary** you compile yourself (`gcc ...`) and drive with a pwntools `process()` — most pwn
  challenges ([Chapter 11](11-pwn.md)).
- A local **Python process** (`python server.py`, or a small Flask app) bound to `127.0.0.1`, driven by
  `process()` or `requests` — the web/SSTI/pickle and jail challenges ([Chapters 8](08-pyjail.md)–[9](09-web.md)).
- A **Docker container**, when the challenge ships a `Dockerfile`.

### Docker pattern

Build from the fetched copy, publish the port **only on the loopback interface**, point your solve at it,
and remove the container afterwards:

```console
$ cd challenges/<name>            # the fetched Dockerfile lives here
$ docker build -t ctfkit-<name> .
$ docker run --rm -d --name ctfkit-<name> -p 127.0.0.1:1337:1337 ctfkit-<name>
$ python examples/chNN/solve_<name>.py   # connects to 127.0.0.1:1337
$ docker rm -f ctfkit-<name>      # always clean up
```

If a challenge ships a `docker-compose.yml`, `docker compose up -d` /
`docker compose down` work the same way — check the compose file binds to
`127.0.0.1`, not `0.0.0.0`. Binding to `127.0.0.1:` keeps the service off your
network; never expose a challenge service beyond your own host.

### Per-challenge extras

The pinned `requirements.txt` covers the core. A few challenges need one extra
package — install it when you reach that chapter, not up front:

| Extra | Needed by | Install |
|-------|-----------|---------|
| `flask` (+ its `jinja2`) | SSTI targets run locally ([Chapter 9](09-web.md)) | `pip install flask` |
| `pydash` | `get_and_set` jail gadget ([Chapter 8](08-pyjail.md)) | `pip install pydash` (version-sensitive) |
| system `libzbar0` | `pyzbar` QR decoding ([Chapter 10](10-forensics.md)) | `apt-get install libzbar0` |

## SageMath is optional

Some organiser solutions used [SageMath](https://www.sagemath.org/) for heavy
algebra (for example the `encrypted-mail` MT19937 recovery). **You do not need
it.** Where a reference solution reached for Sage, `ctfkit` provides a
pure-Python equivalent:

- MT19937 state recovery is done by untempering 624 outputs in
  [`ctfkit.crypto.MT19937`](appendix-c-ctfkit-reference.md) ([Chapter 6](06-attacking-randomness.md)) —
  no Sage, no `GF(2)` linear-algebra package.
- LFSR state recovery is the plain bit bookkeeping in `ctfkit.crypto.LFSR`.

If you *want* Sage for further exploration it runs these challenges too, but
nothing in this course requires it, and the verified solves all run on stock
CPython 3.10 with `requirements.txt`.

## Challenge index (attribution)

Every curated challenge, with its event, author, source repo at the pinned
commit, path, and license. Challenge files are **not** in this repo — fetch them
with `python challenges/fetch.py <name>`. "Chapter" is where the walkthrough (or
exercise) appears; license "none" means "no license; organiser-published for
practice."

Short commit → full hash:

| Repo | Pinned commit |
|------|---------------|
| DownUnderCTF/Challenges_2023_Public | `b48f83db2984bc7fa2ec7879a32d7efb1be8d333` |
| DownUnderCTF/Challenges_2022_Public | `2213706f1a93120bd58b3e47076611d80341c76c` |
| DownUnderCTF/Challenges_2024_Public | `f2797a33d8f5851508f37e854afceedf85eee8a3` |
| ImaginaryCTF/ImaginaryCTF-2023-Challenges | `4a1b779026c3b69a71bef1c8c29eb2e9f8dbee7e` |
| ImaginaryCTF/ImaginaryCTF-2022-Challenges | `ac2f0aa796a651e0eb730db12c3550e4470d4e9c` |
| uclaacm/lactf-archive | `3379d4a7b36680764a34e7dc817cc3c94c244764` |
| hackthebox/cyber-apocalypse-2024 | `4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a` |
| Crusaders-of-Rust/corCTF-2022-public-challenge-archive | `2eaff37d7337fcf6c8a221b415e2f6eed5fafafb` |

### Encoding & scripting

| Challenge | Ch | Event | Author | Repo @ commit · path | License |
|-----------|----|-------|--------|----------------------|---------|
| pyny | [1](01-getting-started.md) | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `beginner/pyny` | none |
| welcome-to-ductf | [2](02-python-for-ctf-data.md) | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `beginner/welcome-to-ductf` | none |
| complementary | [2](02-python-for-ctf-data.md) | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `beginner/complementary` | none |

### Crypto

| Challenge | Ch | Event | Author | Repo @ commit · path | License |
|-----------|----|-------|--------|----------------------|---------|
| rsa | [5](05-rsa.md) | ImaginaryCTF 2023 | Eth007 | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Crypto/rsa` | none |
| greek-cipher | [4](04-classical-and-xor.md) | LA CTF 2023 | ACM Cyber at UCLA | uclaacm/lactf-archive@3379d4a7b3 · `2023/crypto/greek-cipher` | MIT (© 2024 ACM at UCLA) |
| randomly-chosen | [3](03-talking-to-services.md) | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `beginner/randomly-chosen` | none |
| one-more-time-pad | [4](04-classical-and-xor.md) | LA CTF 2023 | ACM Cyber at UCLA | uclaacm/lactf-archive@3379d4a7b3 · `2023/crypto/one-more-time-pad` | MIT |
| primary-knowledge | [5](05-rsa.md) | HTB Cyber Apocalypse 2024 | HackTheBox | hackthebox/cyber-apocalypse-2024@4e59eec7a4 · `crypto/[Very Easy] Primary Knowledge` | none (official write-up repo) |
| apbq-rsa-i | [5](05-rsa.md) | DownUnderCTF 2023 | DUCTF organisers (joseph) | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `crypto/apbq-rsa-i` | none |
| pprngc | [6](06-attacking-randomness.md) | LA CTF 2024 | ACM Cyber at UCLA | uclaacm/lactf-archive@3379d4a7b3 · `2024/crypto/pprngc` | MIT |
| encrypted-mail | [6](06-attacking-randomness.md) | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `crypto/encrypted-mail` | none |
| handshake | exercise | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `crypto/handshake` | none |
| apbq-rsa-ii | exercise | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `crypto/apbq-rsa-ii` | none |

### Reversing

| Challenge | Ch | Event | Author | Repo @ commit · path | License |
|-----------|----|-------|--------|----------------------|---------|
| goated | [7](07-python-reversing.md) | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Reversing/goated` | none |
| impossible | [7](07-python-reversing.md) | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `misc/impossible` | none |
| snailchecker | exercise | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Reversing/snailchecker` | none |

### Pyjail

| Challenge | Ch | Event | Author | Repo @ commit · path | License |
|-----------|----|-------|--------|----------------------|---------|
| helpless | [8](08-pyjail.md) | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `beginner/helpless` | none |
| pycrib | [8](08-pyjail.md) | ImaginaryCTF 2022 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2022-Challenges@ac2f0aa796 · `Misc/pycrib` | none |
| get_and_set | [8](08-pyjail.md) | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Misc/get_and_set` | none |
| you_shall_not_call | [8](08-pyjail.md) | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Misc/you_shall_not_call` | none |
| not-a-pyjail | exercise | DownUnderCTF 2022 | DUCTF organisers | DownUnderCTF/Challenges_2022_Public@2213706f1a · `misc/not-a-pyjail` | none |
| you_shall_not_call-revenge | exercise | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Misc/you_shall_not_call-revenge` | none |

### Web

| Challenge | Ch | Event | Author | Repo @ commit · path | License |
|-----------|----|-------|--------|----------------------|---------|
| parrot-the-emu | [9](09-web.md) | DownUnderCTF 2024 | DUCTF organisers | DownUnderCTF/Challenges_2024_Public@f2797a33d8 · `beginner/parrot-the-emu` | none |
| minigolf | [9](09-web.md) | ImaginaryCTF 2022 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2022-Challenges@ac2f0aa796 · `Web/minigolf` | none |
| sstigolf | [9](09-web.md) | ImaginaryCTF 2022 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2022-Challenges@ac2f0aa796 · `Web/sstigolf` | none |
| were-pickle-phreaks | [9](09-web.md) | HTB Cyber Apocalypse 2024 | HackTheBox | hackthebox/cyber-apocalypse-2024@4e59eec7a4 · `misc/[Easy] Were Pickle Phreaks` | none (official write-up repo) |
| were-pickle-phreaks-revenge | exercise | HTB Cyber Apocalypse 2024 | HackTheBox | hackthebox/cyber-apocalypse-2024@4e59eec7a4 · `misc/[Medium] Were Pickle Phreaks Revenge` | none (official write-up repo) |

### Forensics

| Challenge | Ch | Event | Author | Repo @ commit · path | License |
|-----------|----|-------|--------|----------------------|---------|
| steganographic | [10](10-forensics.md) | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Forensics/steganographic` | none |
| forensics | [10](10-forensics.md) | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Forensics/forensics` | none |
| whack-a-frog | [10](10-forensics.md) | corCTF 2022 | Crusaders of Rust | Crusaders-of-Rust/corCTF-2022-public-challenge-archive@2eaff37d73 · `forensics/whack-a-frog` | AGPL-3.0 (repo-wide) |
| blurry | exercise | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Forensics/blurry` | none |
| blinky-bill | exercise | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `beginner/blinky-bill` | none |

### Pwn

| Challenge | Ch | Event | Author | Repo @ commit · path | License |
|-----------|----|-------|--------|----------------------|---------|
| ret2win | [11](11-pwn.md) | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Pwn/ret2win` | none |
| downunderflow | [11](11-pwn.md) | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `beginner/downunderflow` | none |
| form | [11](11-pwn.md) | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Pwn/form` | none |
| one-byte | [11](11-pwn.md) | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `beginner/one-byte` | none |
| safe-calculator | [11](11-pwn.md) | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `pwn/safe-calculator` | none |
| minimal | [11](11-pwn.md) | ImaginaryCTF 2023 | ICTF organisers | ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026 · `Pwn/minimal` | none |

### Stretch / bonus

| Challenge | Category | Event | Author | Repo @ commit · path | License |
|-----------|----------|-------|--------|----------------------|---------|
| daas | rev | DownUnderCTF 2023 | DUCTF organisers | DownUnderCTF/Challenges_2023_Public@b48f83db29 · `misc/daas` | none |

> On license nuance: LA CTF's repo is MIT (© 2024 ACM at UCLA). corCTF's repo is AGPL-3.0 repo-wide —
> likely inherited from bundled infrastructure tooling rather than a deliberate choice for the challenge
> content, but it is what the repo states, so treat the whole repo as AGPL-covered for citation. The
> DownUnderCTF, ImaginaryCTF, and HackTheBox entries have no `LICENSE` file; they are organiser-published
> for practice (HTB's being an official post-event write-up repo). Attribute, link, and quote only short
> excerpts.

## See also

- [Appendix A — Python-for-CTF Cheat Sheet](appendix-a-python-ctf-cheatsheet.md)
- [Appendix B — pwntools Quick Reference](appendix-b-pwntools-reference.md)
- [Appendix C — `ctfkit` API Reference](appendix-c-ctfkit-reference.md)
- [Chapter 1 — The CTF Mindset and Your Toolbox](01-getting-started.md) builds `fetch.py` and the toolkit skeleton.

Sources for this appendix: [REFERENCES.md](REFERENCES.md#appendix-d--fetching-and-running-challenges-locally)
