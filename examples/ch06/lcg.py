#!/usr/bin/env python3
"""Linear congruential generators: fully predictable once you see the state.

An LCG makes each number from the last: ``x = (a*x + c) mod m``. It is linear,
so it has no secrets once you can see its outputs:

* Know ``a, c, m`` and one output -> every future output is just more
  iterations.
* Know ``m`` and a few consecutive outputs -> solve for ``a`` and ``c`` with one
  modular inverse. ``a = (x2 - x1) * (x1 - x0)^{-1} mod m``, then ``c`` follows.

This is why ``random`` and ``LCG``-based "tokens" are never used for anything
that must stay secret.
"""


class LCG:
    def __init__(self, seed, a, c, m):
        self.state, self.a, self.c, self.m = seed, a, c, m

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state


def recover_a_c(outputs, m):
    x0, x1, x2 = outputs[:3]
    a = (x2 - x1) * pow(x1 - x0, -1, m) % m
    c = (x1 - a * x0) % m
    return a, c


def main() -> None:
    m = 2 ** 31 - 1
    gen = LCG(seed=123456789, a=1103515245, c=12345, m=m)
    outputs = [gen.next() for _ in range(6)]
    print("observed:", outputs[:4], "...")

    a, c = recover_a_c(outputs, m)
    print(f"recovered a={a}, c={c}")

    # Replay from the 3rd output and predict outputs[3:].
    clone = LCG(seed=outputs[2], a=a, c=c, m=m)
    predicted = [clone.next() for _ in range(3)]
    print("predicted:", predicted)
    print("actual   :", outputs[3:])
    print("match    :", predicted == outputs[3:])


if __name__ == "__main__":
    main()
