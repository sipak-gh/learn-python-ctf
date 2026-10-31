# Chapter 12 — Putting It Together: Method, Writeups, and Where Next

You have the tools: `ctfkit`, pwntools, a venv, and seven categories of
technique. What turns tools into solves is **method** — a repeatable way to read
a challenge, pick a direction from its clues, and not waste the clock on dead
ends. This chapter is the playbook. It adds no code (the project is complete at
[`project/ch11/`](11-pwn.md)); it's how to use everything you built. Previous
chapter: [Chapter 11](11-pwn.md).

## The per-challenge checklist

Run the same loop on every challenge — the clue-driven method from
[Chapter 1](01-getting-started.md), made concrete.

1. **Read the prompt twice.** Titles and flavor text are rarely decoration: "one
   more time pad," "the original image reveals all," "complementary," "safe
   calculator" each *named the bug*. Note the flag format (`DUCTF{...}`,
   `ictf{...}`, `lactf{...}`) — a free known-plaintext crib.
2. **Inventory what you were given.** `ls`, then `file` every file. A shipped
   `gen.py`/`corrupt.py`/`source.py` is the answer key; a bundled `libc.so.6`
   screams ret2libc; a leftover `.pyc` leaks bytecode. Note what's *missing*
   too (no private key, no original image).
3. **Identify the category from the artifacts** (table below). This picks your
   first technique, not your last.
4. **Collect clues explicitly.** Write each signal down: a weird constant, `e=3`,
   a reused key, a leaked address, a `printf(user)`, a magic byte. For each, note
   the hypothesis it suggests. One clue, one guess.
5. **Test the cheapest hypothesis first.** A one-liner in the REPL beats a
   100-line script. Dead ends are information — they rule a branch out.
6. **Solve with `ctfkit`.** Reach for the helper the technique needs; write the
   script; run it locally; confirm the real flag against the format.
7. **Generalize.** Name the bug class in one sentence. That sentence is what you
   actually keep.

> **The REPL is your lab.** Python's interactive prompt is where you test clues:
> `int.from_bytes`, a quick `xor`, `dis.dis(fn)`, `rdpcap(...)[0].show()`. Prove
> the idea small before you commit to a file.

## Triage: reading the category from the clues

Most challenges announce their category through their files and prompt. Use this
table to pick where to start:

| You see... | Likely category | First move | Chapter |
|------------|-----------------|-----------|---------|
| A `.py` that is gibberish / superscript / lambdas | encoding or reversing | decode the source; `dis` a `.pyc` | [2](02-python-for-ctf-data.md), [7](07-python-reversing.md) |
| `n, e, c`, a `.pem`, `output.txt` with big ints | crypto (RSA) | parse the key; match the clue to an attack | [5](05-rsa.md) |
| XOR, "pad," a repeating key, Greek letters | crypto (classical/XOR) | crib-drag the flag prefix | [4](04-classical-and-xor.md) |
| `random`, a seed, 624 outputs, an LFSR menu | crypto (PRNG) | brute the seed or recover MT/LFSR state | [6](06-attacking-randomness.md) |
| A host:port, a menu, "connect with nc" | service I/O (any category) | script the protocol with `ctfkit.io`/pwntools | [3](03-talking-to-services.md) |
| `eval`/`exec`, a blacklist, `help()`, a pickle | pyjail / deserialization | introspection chain or opcode craft | [8](08-pyjail.md) |
| A Flask app, `render_template_string`, cookies | web | SSTI probe `{{7*7}}`; pickle over HTTP | [9](09-web.md) |
| A `.pcap`, a `.png`/`.wav`, a corrupted file | forensics | `file`/magic; scapy; diff vs original | [10](10-forensics.md) |
| An ELF, a `win()`, `gets`, a bundled libc | pwn | `checksec`; find the overflow; leak+ROP | [11](11-pwn.md) |

A challenge can sit in two columns (a web app that deserializes pickle; a crypto
service you must script). That's normal — the artifact tells you the *surface*,
the clue tells you the *bug*.

## Time management

- **Timebox each lead.** If a hypothesis hasn't shown progress in ~20 minutes,
  write down why and switch. Fresh eyes on a new challenge beat a stale one.
- **Chase first bloods and low-hanging points.** Solve counts (on most
  scoreboards) estimate difficulty. Early on, hit the many-solve challenges to
  bank points and momentum.
- **Keep a "parked" list.** Note partial progress so you can resume instantly:
  the offset you found, the leak slot, the half-built payload.
- **Know when it's not Python.** If a `.pyc` needs a decompiler, a lattice needs
  more than `sympy`, or a pwn needs the exact remote libc, decide whether to
  install the heavier tool or move on. (Our `encrypted-mail`, `one-byte`, and
  `minimal` are honest examples of that line.)

## Writing a good writeup

Write the solve down, even just for yourself. A writeup is how you *keep* what
you learned and how a team compounds knowledge.

A good writeup has:

- **The prompt and files**, with attribution (event, author, source at a
  commit) — exactly the attribution boxes this course uses.
- **The clues, in order**, and the hypothesis each one triggered. This is the
  valuable part: not just the answer, but *how you knew where to look*.
- **The dead ends.** What you tried that failed, and why. It saves the next
  reader (often future-you) the same wall.
- **The solve script**, runnable, importing your toolkit — and the **real flag
  line** it printed.
- **The bug class in one sentence**, so the lesson outlives the challenge.

> **Why bother?** Writeups are the CTF community's shared memory. Nearly every
> technique in this course was learnable because an organizer or player published
> one. Pay it forward on retired, organizer-published challenges — never leak a
> live event's solutions.

## Organizing your `ctfkit` and notes

`ctfkit` is the course's main artifact because a personal toolkit is what
experienced players carry between events.

- **Grow it, don't fork it per challenge.** When a solve needs a helper you don't
  have, add it to the right module with a test, as each chapter did. Next event
  it's already there. The [`ctfkit` API reference](appendix-c-ctfkit-reference.md)
  is your index.
- **Keep solves as runnable scripts**, one per challenge, each importing
  `ctfkit`. `examples/chNN/solve_*.py` is the template.
- **Pin your environment.** The `requirements.txt` you built is reproducibility:
  a solve that worked last year still runs. Keep per-challenge extras (Flask,
  `pydash`, `libzbar0`) where they belong, not in the core.
- **Fetch, don't vendor, challenge files.** `challenges/fetch.py` +
  `challenges.toml` pull each challenge at a pinned commit into a gitignored
  folder. Your repo stays your own work; see
  [Appendix D](appendix-d-running-challenges.md).

## Teamwork

CTFs are usually team sports. What makes a team fast:

- **Claim challenges** so two people don't silently duplicate work.
- **Share leaks and state**, not just flags: "offset is 72," "SSTI works but `_`
  is blacklisted," "libc is glibc 2.35." A half-solve handed off is often a full
  solve.
- **Pair on hard ones.** One drives the REPL, one reads the source. The
  clue-spotting goes faster out loud.
- **Pool toolkits.** A shared `ctfkit` means everyone benefits when one person
  automates a technique.

## Legal and ethical practice

This is non-negotiable — the frame for everything above, and the same rule from
[Chapter 1](01-getting-started.md) and the course [README](README.md):

- **Only solve what you are authorized to.** Everything here is a **retired,
  organizer-published** challenge, pinned and attributed. Nothing live, nothing
  scraped.
- **Everything runs locally.** Every service is your own Docker container or
  local process; every `remote()`/connection targets **127.0.0.1** — your own
  machine. Never connect to, scan, or script against any live, remote,
  third-party, or competition server.
- **Respect each source's terms.** Platforms like CryptoHack, OverTheWire, and
  active HackTheBox content are *further practice only* — never publish
  OverTheWire passwords or active-machine solutions.
- These techniques are for **defensive understanding** of bug classes on
  consenting, self-hosted targets. Not for attacking systems you don't own or
  lack permission to test.

## Where to go next

Pick targets that are **retired and published**, and keep the local-only,
authorized-only rule.

- **picoCTF / picoGym** — https://picoctf.org/ . Beginner-friendly, always-on
  practice gym; excellent for drilling fundamentals in every category.
- **Archive repos you already know** — the DownUnderCTF, ImaginaryCTF, and LA CTF
  public archives this course draws from have many more challenges at the same
  commits. Pick by solve count (start high) and category you want to strengthen.
- **CryptoHack** — https://cryptohack.org/ . Structured crypto courses and
  challenges. Great for RSA/PRNG/lattice depth. Respect their platform terms;
  solve on-site.
- **pwn.college** — https://pwn.college/ . A free, structured curriculum for
  binary exploitation and systems security — the natural continuation of
  [Chapter 11](11-pwn.md).
- **OverTheWire** (e.g. Bandit, Narnia) — https://overthewire.org/wargames/ .
  Classic wargames for shell and binary skills. **Never publish level
  passwords.**

### Methodology references

- **CTF Field Guide** (Trail of Bits) — https://trailofbits.github.io/ctf/ .
  Category-by-category methodology from a leading security firm.
- **CTF 101** (OSIRIS Lab, NYU) — https://ctf101.org/ . A concise, categorized
  reference wiki.
- **pwntools docs** — https://docs.pwntools.com/ . The authoritative pwn
  reference; pair with [Appendix B](appendix-b-pwntools-reference.md).

## Capstone: solve one yourself

No walkthrough this time. Apply the checklist end to end on a challenge we
deliberately left unsolved.

> Challenge: **not-a-pyjail** — DownUnderCTF 2022 by hashkitten. Source:
> `DownUnderCTF/Challenges_2022_Public@2213706f` (`misc/not-a-pyjail`).
> License: none (organizer-published for practice). Fetch it:
> `python challenges/fetch.py not-a-pyjail`, then read `src/not-a-pyjail.py` and
> run it locally in its Docker (bound to 127.0.0.1).

Work the method: read the prompt, inventory the files, spot the clue, form a
hypothesis, test it small, then script it. Only open the hints if you're stuck.

<details><summary>Clue hints (open one at a time)</summary>

1. The author's joke is the whole premise: "I've decided to **not execute
   anything at all**." The program *parses* or *inspects* your input but claims
   never to run it. Where, exactly, does it stop short of running code — and is
   that really true?
2. Think about what Python does *before* and *around* `exec`. Reading a value,
   displaying a result, or comparing objects can trigger **dunder methods**
   (`__repr__`, `__eq__`, `__getattr__`, ...). Code that runs "just from looking
   at" an object is still code running.
3. You don't need a classic `eval` escape. You need the checker to *touch* an
   object you control in a way that invokes your method. Build the object so the
   touch does the work — then use the object-introspection chain from
   [Chapter 8](08-pyjail.md) to reach the flag file. Run everything against your
   own local container on 127.0.0.1, and tear it down afterward.

</details>

## Summary

- Run the **same loop** every time: read, inventory, categorize, collect clues,
  test cheap, solve with `ctfkit`, generalize.
- **Triage from artifacts**; let the clue name the bug.
- **Timebox** leads, chase high-solve challenges first, and park partial
  progress.
- **Write it down.** Clues, dead ends, script, flag, bug class — that's how the
  skill compounds and how the community learns.
- Grow one **`ctfkit`**, pin your environment, fetch (don't vendor) challenges.
- **Stay legal:** retired, authorized, local-only, 127.0.0.1. Always.
- Keep going: picoCTF, the archives, CryptoHack, pwn.college, OverTheWire — and
  the Field Guide / CTF 101 / pwntools docs to go deeper.

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-12--putting-it-together-method-writeups-and-where-next)
