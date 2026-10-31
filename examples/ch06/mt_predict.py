#!/usr/bin/env python3
"""MT19937 state recovery: untemper 624 outputs, then predict every future one.

Python's ``random`` is a Mersenne Twister. Its internal state is 624 32-bit
words. Each output is one state word run through a reversible "tempering" of
shifts, XORs and masks. Reverse that tempering (``ctfkit.crypto.untemper``) on
624 consecutive 32-bit outputs and you have rebuilt the entire state -- so you
can clone the generator and predict all future values exactly. No seed needed.

The clue in a challenge: a server leaks a run of full 32-bit ``getrandbits(32)``
(or token) values. 624 of them is game over.
"""
import random

from ctfkit.crypto import MT19937, untemper


def main() -> None:
    # untemper is the exact inverse of MT's output tempering.
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


if __name__ == "__main__":
    main()
