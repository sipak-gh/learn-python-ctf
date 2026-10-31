#!/usr/bin/env python3
"""LFSRs: linear feedback over GF(2), and why linear means predictable.

A linear-feedback shift register shifts out one bit per clock and feeds a XOR of
"tap" positions back in. Because every bit is a XOR (linear over GF(2)), the
output stream is a linear function of the initial register -- so watching enough
output bits lets you reconstruct the state. ``ctfkit.crypto.LFSR`` clocks the
register's last bit out, so the first ``width`` outputs are the initial state in
shift-out (reversed) order; ``recover_state`` reverses them back for you. From
the recovered state you clock forward to predict.

This linearity is exactly the lever the chapter's ``pprngc`` solve pulls.
"""
from ctfkit.crypto import LFSR


def main() -> None:
    taps = [0, 2]                       # feedback = state[0] ^ state[2]
    width = 5
    secret = [1, 0, 1, 1, 0]

    gen = LFSR(list(secret), taps)
    observed = gen.bits(width)          # attacker sees these output bits
    print("output bits:", observed)

    recovered = LFSR.recover_state(observed, taps, width)
    print("recovered  :", recovered, " match=", recovered == secret)

    # Re-seed a clone with the recovered state and predict the next bits.
    clone = LFSR(recovered, taps)
    clone.bits(width)                   # fast-forward past what we already saw
    truth = LFSR(list(secret), taps)
    truth.bits(width)
    predicted = clone.bits(6)
    actual = truth.bits(6)
    print("predicted  :", predicted)
    print("actual     :", actual, " match=", predicted == actual)


if __name__ == "__main__":
    main()
