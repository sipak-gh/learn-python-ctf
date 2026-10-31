#!/usr/bin/env python3
"""Solve DownUnderCTF 2023 `welcome-to-ductf` -- the text is upside-down.

Recon: the distributed file `upside-down.a++` is a joke esolang ("Aussie++")
printed upside-down with Unicode homoglyphs (`ƃɐlɟ`, `H∀Ǝ⅄`). The README even
says "Try reading bottom up!".

Clue: upside-down + mirrored text means two reversible transforms:
  1. reverse the order of lines and of characters within each line;
  2. map each flipped Unicode glyph back to its ASCII letter via a flip table.

You do NOT need to run the esolang. Once flipped, the program builds the flag
by string concatenation: `GIMME GLAF + HappyHour + STREWTH`. Resolve those
three variables and join them.

Fetch first:  python challenges/fetch.py welcome-to-ductf
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "welcome-to-ductf", "src", "upside-down.a++")

# The author's flip table (pairs of normal<->flipped glyphs).
_FLIPS = ['?', '¿', "'", ',', ',', "'", '[', ']', ']', '[', '!', '¡', 'a', 'ɐ',
          'b', 'q', 'c', 'ɔ', 'd', 'p', 'e', 'ǝ', 'f', 'ɟ', 'g', 'ƃ', 'h', 'ɥ',
          'i', 'ᴉ', 'j', 'ɾ', 'k', 'ʞ', 'l', 'l', 'm', 'ɯ', 'n', 'u', 'p', 'd',
          'q', 'b', 'r', 'ɹ', 's', 's', 't', 'ʇ', 'u', 'n', 'v', 'ʌ', 'w', 'ʍ',
          'x', 'x', 'y', 'ʎ', 'z', 'z', 'A', '∀', 'B', 'q', 'C', 'Ɔ', 'D', 'D',
          'E', 'Ǝ', 'F', 'Ⅎ', 'G', 'פ', 'I', 'I', 'F', 'ſ', 'K', 'ʞ', 'L', '˥',
          'M', 'W', 'N', 'N', 'O', 'O', 'P', 'Ԁ', 'Q', 'Q', 'R', 'ɹ', 'S', 'S',
          'T', '┴', 'U', '∩', 'V', 'Λ', 'W', 'M', 'X', 'X', 'Y', '⅄', 'Z', 'Z',
          '0', '0', '1', 'Ɩ', '2', 'ᄅ', '3', 'Ɛ', '4', 'ㄣ', '5', 'ϛ', '6', '9',
          '7', 'ㄥ', '8', '8', '9', '6', '(', ')', ')', '(', '<', '>', '>', '<',
          '"', '„']
FLIPS = {_FLIPS[i]: _FLIPS[i + 1] for i in range(0, len(_FLIPS), 2)}
FLIPS |= {_FLIPS[i + 1]: _FLIPS[i] for i in range(0, len(_FLIPS), 2)}


def flip(text: str) -> str:
    lines = text.splitlines()
    chars = list("\n".join(line[::-1] for line in lines[::-1]))
    return "".join(FLIPS.get(c, c) for c in chars)


def main() -> None:
    upside_down = open(CHALL, encoding="utf-8").read()
    source = flip(upside_down)
    print("flipped source:\n" + source + "\n")

    # Collect every `I RECKON <name> = "<value>";` assignment...
    env = dict(re.findall(r'I RECKON (\S+) = "([^"]*)"', source))
    # ...then obey the final concatenation `GIMME A + B + C;`.
    gimme = re.search(r"GIMME\s+(\S+ \+ \S+ \+ \S+);", source)
    names = [n.strip() for n in gimme.group(1).split("+")]
    flag = "".join(env[n] for n in names)
    print("FLAG:", flag)


if __name__ == "__main__":
    main()
