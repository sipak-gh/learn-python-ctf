#!/usr/bin/env python3
"""Solve LA CTF 2024 `pprngc` -- a predict-the-next-bit LFSR oracle.

Recon: the service wraps `f`, a 16-bit->16-bit state update built from a
length-7 LFSR, a length-5 LFSR, and a 4-bit counter over a secret bit
permutation. It leaks `f(seed)` up front and offers four options: emit PRNG
output, apply `f` (<=15 times), "predict next bit" via `pprngc` (<=16 times),
and guess the seed for the flag.

Clue: `pprngc(pred, stream)` walks the stream BACKWARD with `f_inverse`,
checking each `compute_output_bit(state, pred)`. Feed it a stream that is our
known 16 forward states (from option 2) plus the fixed 16-bit prefix (option
1), with a one-hot predicate `2**i`. `compute_output_bit(state, 2**i)` is just
bit i, so the oracle hands back one seed bit per query. Sixteen queries ->
whole seed -> option 4 -> flag.

We run the challenge as a LOCAL process (never a remote host) and read the
flag it prints.

Fetch first:  python challenges/fetch.py pprngc
"""
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

    states = [first_state]  # chain f() forward 15 times (option 2)
    for _ in range(15):
        conn.sendlineafter(b"guess seed ", b"2")
        conn.sendlineafter(b"Gimme a number! ", str(states[-1]).encode())
        states.append(int(conn.recvline().decode().strip()))

    conn.sendlineafter(b"guess seed ", b"1")
    prefix = conn.recvline().decode().strip()[:16]

    preds = [2 ** i for i in range(16)]
    seed_bits = []
    for i in range(16):
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


if __name__ == "__main__":
    main()
