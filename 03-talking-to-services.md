# Chapter 3 — Talking to Services and Automating

Many challenges aren't a file — they're a *service* you connect to over TCP that prompts, reads your
reply, and loops. This chapter does the conversation by hand with `socket`, shows why that's tedious, then
hands you **pwntools**, the practitioner's tool. You'll build `ctfkit.io`, solve a PRNG challenge, and
prove the automation loop against a local service. Previous: [Chapter 2](02-python-for-ctf-data.md). Next:
[Chapter 4](04-classical-and-xor.md).

> **Scope reminder:** point these tools only at a service you're allowed to touch — in this course always
> your **own local** process or Docker container on `127.0.0.1`. Never connect to live competition
> infrastructure or any host you don't control.

## A TCP conversation by hand

A challenge service follows a simple pattern: print a **prompt**, you send a **line**, it replies, repeat.
The stdlib `socket` does all of it. Doing it once by hand shows what pwntools automates later.

The two primitives you need:

- **recv-until**: read bytes until a delimiter appears (usually a prompt like `"> "`). TCP is a stream, so
  one `recv()` may return a partial line or several — you buffer and scan.
- **send-line**: send your reply **plus a newline**, because the server reads a line at a time.

To stay self-contained and local, the example starts a throwaway echo server on `127.0.0.1` in a
background thread, then connects two ways: raw socket, then `ctfkit.Service`.

`examples/ch03/socket_by_hand.py`

```python
import socket
import threading

from ctfkit.io import Service


def start_server() -> int:
    """A throwaway local server: prompt, read a line, reply. Returns its port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))        # port 0 = let the OS pick a free one
    srv.listen(1)
    port = srv.getsockname()[1]

    def handle():
        conn, _ = srv.accept()
        conn.sendall(b"name> ")
        name = conn.recv(1024).strip()
        conn.sendall(b"hello " + name + b"\n")
        conn.close()
        srv.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


def by_hand(port: int) -> None:
    """The raw-socket version: buffer bytes, find the prompt, send a line."""
    sock = socket.create_connection(("127.0.0.1", port))
    buf = b""
    while b"> " not in buf:              # recv until we see the prompt
        buf += sock.recv(4096)
    print("raw prompt:", buf.decode().strip())
    sock.sendall(b"world\n")             # you must add the newline yourself
    print("raw reply :", sock.recv(4096).decode().strip())
    sock.close()


def with_ctfkit(port: int) -> None:
    """The same conversation through ctfkit.Service -- intent is obvious."""
    with Service("127.0.0.1", port) as svc:
        prompt = svc.recv_until(b"> ")
        print("svc prompt:", prompt.decode().strip())
        svc.send_line(b"world")
        print("svc reply :", svc.recv_line().decode())


if __name__ == "__main__":
    by_hand(start_server())
    with_ctfkit(start_server())
```

```console
$ python examples/ch03/socket_by_hand.py
raw prompt: name>
raw reply : hello world
svc prompt: name>
svc reply : hello world
```

The raw version shows the friction: you manage a buffer, add `\n` by hand, call `.strip()` everywhere,
decode manually, and handle no timeouts. Across a dozen round-trips it's error-prone — motivation for a
wrapper, and then for pwntools.

## pwntools: tubes

**pwntools** is the standard CTF automation library. Its core abstraction is a **tube**: a bidirectional
byte stream with handy read/write methods. The same API works whether the other end is a local process or
a remote socket:

- `process([...])` — launch a local program and talk to its stdin/stdout.
- `remote(host, port)` — connect to a TCP service (for us, always `127.0.0.1`).

The methods you'll use constantly:

| Method | Does |
|---|---|
| `recvuntil(delim)` | read until `delim` appears |
| `recvline()` | read one line (including the `\n`) |
| `sendline(data)` | send `data` + `\n` |
| `sendlineafter(delim, data)` | wait for `delim`, then `sendline(data)` |
| `interactive()` | hand the tube to your keyboard (great for a popped shell) |
| `context.log_level` | `"debug"` to watch every byte, `"error"` to hush |

Here's an adder driven with pwntools `process()` against a tiny local script:

`examples/ch03/adder_service.py`

```python
print("== adder service ==")
a = int(input("a> "))
b = int(input("b> "))
print("sum:", a + b)
print("bye")
```

`examples/ch03/pwntools_process.py`

```python
import os

from pwn import context, process

context.log_level = "error"   # hush pwntools' own status lines

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "adder_service.py")

io = process(["python3", TARGET])
io.recvuntil(b"== adder service ==\n")

# sendlineafter waits for the prompt, then sends the line + newline.
io.sendlineafter(b"a> ", b"2")
io.sendlineafter(b"b> ", b"40")

line = io.recvline().strip()          # b"sum: 42"
print("got:", line.decode())
print("sum value:", int(line.split(b":")[1]))

io.close()
```

```console
$ python examples/ch03/pwntools_process.py
got: sum: 42
sum value: 42
```

`sendlineafter(b"a> ", b"2")` replaces the whole "recv until prompt, then sendline" dance with one call.
To connect to a service instead of launching one, only the first line changes:

```python
from pwn import remote
io = remote("127.0.0.1", 1337)   # your own local container; everything else is identical
```

> **Tip:** set `context.log_level = "debug"` while developing to see every byte sent and received — it's
> the fastest way to find out why a `recvuntil` is hanging (usually your delimiter doesn't match the exact
> prompt bytes). Set it back to `"error"` for a clean final run.

## Running a Dockerized challenge locally

When a challenge ships a `Dockerfile`, you run *its* server on your own machine and point pwntools at
`127.0.0.1`. The pattern, never touching anyone's infrastructure:

```console
$ cd challenges/<name>
$ docker build -t ctfkit-<name> .
$ docker run --rm -d -p 127.0.0.1:1337:1337 --label ctfkit ctfkit-<name>
$ # ... run your solve against remote("127.0.0.1", 1337) ...
$ docker rm -f $(docker ps -q --filter label=ctfkit)
```

Key points:

- `-p 127.0.0.1:1337:1337` binds the port to loopback only, so nothing is exposed to your network.
- `--label ctfkit` tags the container so you can find and remove it afterward.
- Always `docker rm -f` when done. Leaving containers running is both messy and a footgun.

Most challenges here run as a plain local Python process (like the adder) or a local Flask app
([Chapter 9](09-web.md)); Docker is only for the few that bundle a full server image.

## Building ctfkit: `ctfkit.io`

`ctfkit.io` gives you two things: `Service`, a hand-rolled socket wrapper (so you understand the
mechanics), and `pwn_tube`, a one-liner to the pwntools equivalent (what you reach for under time
pressure). Create `ctfkit/io.py`.

The `Service` class — connect, buffer, and the recv-until primitive:

```python
"""Service I/O: talk to a challenge over a socket, then over pwntools.

Scope / ethics: only ever point these at a service you are allowed to touch --
your own local container on 127.0.0.1.
"""
from __future__ import annotations

import socket
import time

__all__ = ["Service", "pwn_tube"]


class Service:
    """A minimal recv-until / send-line TCP client built on socket."""

    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = bytearray()

    def recv(self, n: int = 4096) -> bytes:
        """Read up to n bytes, draining the internal buffer first."""
        if self._buf:
            chunk = bytes(self._buf[:n])
            del self._buf[:n]
            return chunk
        return self.sock.recv(n)

    def recv_until(self, delim: bytes | str, drop: bool = False) -> bytes:
        """Read until delim appears; the core 'wait for the prompt' primitive."""
        if isinstance(delim, str):
            delim = delim.encode()
        deadline = time.monotonic() + self.timeout
        while delim not in self._buf:
            if time.monotonic() > deadline:
                raise TimeoutError(f"never saw {delim!r}; buffer={bytes(self._buf)!r}")
            data = self.sock.recv(4096)
            if not data:
                raise EOFError(f"connection closed; buffer={bytes(self._buf)!r}")
            self._buf.extend(data)
        idx = self._buf.index(delim) + len(delim)
        out = bytes(self._buf[:idx])
        del self._buf[:idx]
        return out[: -len(delim)] if drop else out
```

The send side, a convenience, cleanup, and context-manager support:

```python
    def recv_line(self, drop: bool = True) -> bytes:
        """Read one \\n-terminated line (newline stripped by default)."""
        return self.recv_until(b"\n", drop=drop)

    def send(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data)

    def send_line(self, data: bytes | str = b"") -> None:
        """Send data followed by a newline."""
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + b"\n")

    def send_line_after(self, delim: bytes | str, data: bytes | str) -> bytes:
        """Wait for delim, then send data + newline. Returns what was read."""
        got = self.recv_until(delim)
        self.send_line(data)
        return got

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "Service":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
```

And the pwntools-backed tube — imported lazily so `ctfkit` stays importable without pwntools:

```python
def pwn_tube(host: str, port: int, **kwargs):
    """Return a pwntools `remote` tube for the same job as Service.

    Only use this against your own local container (127.0.0.1).
    """
    from pwn import remote

    return remote(host, port, **kwargs)
```

`Service.recv_until` mirrors pwntools' `recvuntil`, and `send_line_after` mirrors `sendlineafter` —
deliberately, so once you know the pwntools names, the hand-rolled version reads the same and you see what
the library does for you.

### Checkpoint

Add `tests/test_io.py`. It stands up a local echo server in a thread (our ethics model exactly) and drives
it through `Service`:

```python
import socket
import threading

from ctfkit import io


def _echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def handle():
        conn, _ = srv.accept()
        conn.sendall(b"name> ")
        data = conn.recv(1024)
        conn.sendall(b"hello " + data)
        conn.close()
        srv.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


def test_service_recv_until_and_send_line():
    port = _echo_server()
    with io.Service("127.0.0.1", port, timeout=5) as svc:
        prompt = svc.recv_until(b"> ")
        assert prompt == b"name> "
        svc.send_line(b"world")
        line = svc.recv_line()
        assert line == b"hello world"
```

```console
$ pytest -q
......                                                                   [100%]
6 passed in 0.02s
```

The complete project at this point is in `project/ch03/`.

## Challenge walkthrough: randomly-chosen

> **Challenge:** `randomly-chosen` — DownUnderCTF 2023 by joseph. Source:
> `DownUnderCTF/Challenges_2023_Public`@`b48f83db29` (`beginner/randomly-chosen`).
> License: none (organizer-published for practice).

This one is *offline* (it ships an `output.txt`), but it's your first taste of attacking Python's `random`,
and shows the automation mindset even without a socket.

### Recon

```console
$ python challenges/fetch.py randomly-chosen
$ ls challenges/randomly-chosen/src
flag.txt  output.txt  randomly-chosen.py
```

The generator is four lines:

```python
import random

random.seed(random.randrange(0, 1337))
flag = open('./flag.txt', 'r').read().strip()
out = ''.join(random.choices(flag, k=len(flag)*5))
print(out)
```

`output.txt` is a 305-character jumble of the flag's own characters.

### Clues

> **Clue:** `random.seed(random.randrange(0, 1337))` seeds the PRNG with a value in **0–1336**. That's a
> tiny keyspace — 1337 possibilities. You can brute-force *all* of them offline.

> **Clue (HINTS.md):** `random.choices(flag, k=...)` picks characters *from the flag*. If you know the
> seed, you know exactly which indices it picked, so you can reverse the scramble and rebuild the flag.
> The `DUCTF{...}` format confirms the right seed.

Python's `random` is a **Mersenne Twister** — fully deterministic given its seed. Seed it the same way and
it replays the identical sequence. [Chapter 6](06-attacking-randomness.md) attacks it when the seed *isn't*
tiny; here, brute force is enough.

### Test the hypothesis

`random.choices(population, k)` draws each pick as `population[int(random() * len(population))]`. So for a
guessed seed, re-seed and replay `int(random() * length)` for each output character to learn which flag
index it came from. Fill a `flag` array; if it comes out complete, consistent, and starts with `DUCTF{`,
the seed was right.

One unknown: you don't know `len(flag)` up front. But `len(output) == 5 * len(flag)`, so the length is
fixed by the output — `length = len(out) // 5`.

### Solve

`examples/ch03/solve_randomly_chosen.py`

```python
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(REPO, "challenges", "randomly-chosen", "src", "output.txt")


def try_seed(seed, out, length):
    random.seed(seed)
    flag = [None] * length
    # mirror random.choices(population, k): index = int(random()*length)
    for ch in out:
        idx = int(random.random() * length)
        if flag[idx] is None:
            flag[idx] = ch
        elif flag[idx] != ch:
            return None            # contradiction -> wrong seed
    if None in flag:
        return None                # some index never filled -> wrong seed
    return "".join(flag)


def main() -> None:
    out = open(OUT).read().strip()
    length = len(out) // 5
    for seed in range(1337):
        cand = try_seed(seed, out, length)
        if cand and cand.startswith("DUCTF{"):
            print("seed =", seed)
            print("FLAG:", cand)
            return
    print("no seed found")


if __name__ == "__main__":
    main()
```

```console
$ python examples/ch03/solve_randomly_chosen.py
seed = 252
FLAG: DUCTF{is_r4nd0mn3ss_d3t3rm1n1st1c?_cba67ea78f19bcaefd9068f1a}
```

> **⚠ Note:** the seed prints as `252` here because `random.seed(int)` is deterministic across machines.
> The lesson isn't the number — it's that a 1337-value keyspace falls to brute force instantly.

### Why it worked / generalize

The bug is a **small-seed PRNG**: a deterministic generator seeded from a tiny range isn't random at all —
replay every value by trying each seed. This generalizes to any offline oracle: when the secret space is
small, **brute-force it and check against a known format.** When the keyspace is too big to brute, you
recover the generator's internal state instead — [Chapter 6](06-attacking-randomness.md).

## Proving the automation loop

`randomly-chosen` was offline, but the pwntools skills matter the moment a challenge is a live (local!)
service. The `pwntools_process.py` run above *is* that proof in miniature: connect, `recvuntil` the prompt,
`sendlineafter` your answer, parse the reply — the exact loop you'll run against a
`remote("127.0.0.1", PORT)` container later (the PRNG service in
[Chapter 6](06-attacking-randomness.md), the pwn targets in [Chapter 11](11-pwn.md)). Swap `process([...])`
for `remote("127.0.0.1", PORT)` and nothing else changes.

## Summary

- A service is a prompt-and-reply loop over TCP. The two primitives are **recv-until** (wait for a prompt)
  and **send-line** (reply + `\n`).
- Doing it with raw `socket` works but is fiddly: manual buffering, newlines, decoding, timeouts.
- **pwntools** tubes (`process`, `remote`) give `recvuntil` / `sendline` / `sendlineafter` / `interactive`
  and the same API for local and networked targets. `context.log_level = "debug"` shows every byte.
- Dockerized challenges run on your own machine bound to `127.0.0.1`; label and `docker rm -f` them after.
- `ctfkit.io` provides `Service` (hand-rolled) and `pwn_tube` (pwntools-backed) with matching method names.
- `randomly-chosen` showed small-seed PRNG recovery: brute all 1337 seeds offline and confirm with the flag
  format.

## Exercises

1. **recv_until with drop.** Using the local echo server from `socket_by_hand.py`, read the prompt with
   `svc.recv_until(b"> ", drop=True)` and confirm the delimiter is stripped.

   <details><summary>Solution</summary>

   ```python
   with Service("127.0.0.1", port) as svc:
       print(svc.recv_until(b"> ", drop=True))   # b'name' -- the '> ' is gone
   ```

   `drop=True` returns everything up to the delimiter without it — handy when you only want the text
   before a prompt.
   </details>

2. **pwntools parsing.** Modify `pwntools_process.py` to send `a=100`, `b=23` and assert the parsed sum is
   `123`.

   <details><summary>Solution</summary>

   ```python
   io.sendlineafter(b"a> ", b"100")
   io.sendlineafter(b"b> ", b"23")
   assert int(io.recvline().strip().split(b":")[1]) == 123
   ```

   Same loop, different inputs — that's the point of scripting the interaction.
   </details>

3. **Why newlines matter.** Delete the `+ b"\n"` from `Service.send_line` (or send with `svc.send` instead
   of `send_line`) against the echo server and explain what happens.

   <details><summary>Solution</summary>

   The server's `conn.recv(1024)` may still return your bytes, but a server that reads a *line* (`input()`
   or `readline()`) **blocks forever** waiting for the newline that never comes. That hang is the most
   common "my script is stuck" bug. Always terminate lines — which is why `send_line` / `sendline` exist.
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-3--talking-to-services-and-automating)
