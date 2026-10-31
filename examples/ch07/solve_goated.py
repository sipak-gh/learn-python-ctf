#!/usr/bin/env python3
"""Solve ImaginaryCTF `goated` -- Church-encoded lambda calculus.

Recon: `goated.py` is one giant expression of nested lambdas
(`print((... )("Well done!")("Try again...")))`). It is lambda-calculus: the
program turns your input into a Church-encoded list of bits, does arithmetic,
and compares against a hardcoded list.

Clue: you don't have to execute the obfuscation, you have to *read its shape*.
The comparison is `ADD(MUL(input)(a))(b) == c`, i.e. `input*a + b == c`. Peel
the matching-parenthesis groups to isolate the three Church numerals a, b, c,
decode them to integers, then recover `input = (c - b) // a` and turn it back
into bytes. Per the README the result is the flag body (wrap in `ictf{...}`).

Fetch first:  python challenges/fetch.py goated
"""
import os

from ctfkit.encoding import long_to_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SRC = os.path.join(REPO, "challenges", "goated", "challenge", "goated.py")


def matching_paren(s):
    """Split s into (first fully-parenthesised group, remainder)."""
    depth, i = 1, 1
    while depth > 0:
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
        i += 1
    return s[:i], s[i:]

# Church-list decoders (the encoding goated.py uses for its numbers).
head = lambda lst: lst(lambda a: lambda b: b)(lambda a: lambda b: a)
tail = lambda lst: lst(lambda a: lambda b: b)(lambda a: lambda b: b)
isempty = lambda lst: lst(lambda a: lambda b: a)(True)(False)


def bdec(b):
    out = ""
    while not isempty(b):
        out += head(b)("1")("0")
        b = tail(b)
    return int(out[::-1], 2) if out else 0


def main() -> None:
    goat = (open(SRC).read().strip()
            .replace("print((", "")
            .replace(')("Well done!")("Try again..."))', ""))
    _listeq, goat = matching_paren(goat)
    c, goat = matching_paren(goat)
    userinput, goat = matching_paren(goat)
    userinput = userinput[1:-1]
    _add, userinput = matching_paren(userinput)
    mulres, userinput = matching_paren(userinput)
    b, _ = matching_paren(userinput)
    mulres = mulres[1:-1]
    _mul, mulres = matching_paren(mulres)
    _inp, mulres = matching_paren(mulres)
    a, _ = matching_paren(mulres)

    a, b, c = bdec(eval(a)), bdec(eval(b)), bdec(eval(c))
    x = (c - b) // a
    body = long_to_bytes(x).decode("latin-1")
    print("recovered input:", body)
    print("FLAG:", f"ictf{{{body}}}")


if __name__ == "__main__":
    main()
