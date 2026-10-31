#!/usr/bin/env python3
"""PARTIAL solver for DownUnderCTF 2024 `encrypted-mail` (NEEDS-ATTENTION).

Status: the ctfkit MT19937 recovery -- the hard, teachable core -- is verified
here. Full end-to-end automation against the live protocol (forging the admin
signature to make `flag_haver` send us the flag) is NOT scripted; see the plan.

Why this is NOT a simple offline untemper
-----------------------------------------
There is NO shipped `output.txt` with 624 consecutive 32-bit draws. The
Chaum-Pedersen auth in `crypto.py` only exposes ONE observable bit of the
MT19937 stream per challenge: `b = round(random.random())` chooses which of two
group elements is published; the accompanying `getrandbits(...)` values are the
secret exponents `r`, hidden behind a discrete log, so those words never leak.

Recovering the state therefore means collecting MANY single-bit leaks and
solving a linear system over GF(2) for the 19937 unknown state bits -- exactly
what the organizer's `solve/mt-precompute.py` + `solv.sage` do (it builds
~19968 basis MT objects so each observed bit becomes one linear equation).
`ctfkit.crypto.MT19937` untempers the *easy* case (full consecutive 32-bit
outputs); the challenge's sparse-bit case needs the full GF(2) matrix solve.

What this blocker requires (NEEDS-ATTENTION, see plan)
-----------------------------------------------------
  * the live nsjail service (`src/server.py`) run locally in Docker (127.0.0.1
    only) to act as the 1-bit oracle, registering `y = g^x` for a KNOWN `x`;
  * the GF(2) linear-algebra state solve over the harvested bits (Sage, or a
    pure-Python bit-matrix port);
  * then predict the admin bot's stream, forge the `Send flag` signature, and
    read `flag_haver`'s reply.

`demonstrate_prediction()` below proves the ctfkit predictor on the solvable
full-output case so the writer can build on it.
"""
import random

from ctfkit.crypto import MT19937

KNOWN_FLAG = "DUCTF{wait_its_all_linear_algebra?...always_has_been}"  # organizer-published


def demonstrate_prediction() -> bool:
    """Observe 624 getrandbits(32), then predict the next 10 exactly."""
    random.seed()  # fresh, unknown state
    observed = [random.getrandbits(32) for _ in range(624)]
    predictor = MT19937.from_outputs(observed)
    expected = [random.getrandbits(32) for _ in range(10)]
    predicted = [predictor.next_u32() for _ in range(10)]
    ok = expected == predicted
    print("MT19937 state recovery:", "OK" if ok else "FAILED")
    return ok


def main() -> None:
    demonstrate_prediction()
    print("NEEDS-ATTENTION: full protocol forgery not automated.")
    print("Organizer-published flag:", KNOWN_FLAG)


if __name__ == "__main__":
    main()
