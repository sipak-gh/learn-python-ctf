#!/usr/bin/env python3
"""Solve LA CTF 2023 `greek-cipher` -- monoalphabetic substitution, crib dragged.

Recon: `greek.txt` is English with every Latin letter swapped for a Greek one.
That is a monoalphabetic substitution cipher: one cipher letter always maps to
the same plaintext letter.

Clue: two cribs break it wide open.
  * The flag format: the token containing `{` must be `lactf{...}`.
  * Readable structure: the text is ordinary English prose, so guessing the
    opening sentence ("did you know that julius caesar...") pins most letters.

We align our guessed plaintext words to the ciphertext words position by
position to build the cipher->plain map, then decrypt everything and read the
flag. This is exactly how you solve an "aristocrat" by hand, just scripted.

Fetch first:  python challenges/fetch.py greek-cipher
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "greek-cipher", "greek.txt")

# Our hypothesis for the (readable) plaintext, used only to learn the mapping.
# A solver writes this down as they recognise words; it need not be complete.
CRIB = (
    "did you know that julius caesar was not the first person in history "
    "suspected of using encryption me neither did you know that julius caesar "
    "was probably fluent in greek me neither i like how greek character look "
    "though even if i cant read them"
).split()


def build_map(cipher_words, crib_words):
    mapping = {}
    for cw, pw in zip(cipher_words, crib_words):
        cw = cw.strip("?.,!{}'")
        pw = pw.strip("?.,!'")
        if len(cw) != len(pw):
            continue  # skip words that don't line up (punctuation differences)
        for c, p in zip(cw, pw):
            mapping[c] = p
    return mapping


def main() -> None:
    ciphertext = open(CHALL, encoding="utf-8").read().strip()
    mapping = build_map(ciphertext.split(), CRIB)
    decoded = "".join(mapping.get(ch, ch) for ch in ciphertext)
    print(decoded)
    match = re.search(r"lactf\{[^}]*\}", decoded)
    print("\nFLAG:", match.group(0) if match else "not found")


if __name__ == "__main__":
    main()
