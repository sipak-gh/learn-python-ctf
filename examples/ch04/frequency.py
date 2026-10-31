#!/usr/bin/env python3
"""Frequency analysis: score text by how close its letter counts are to English.

A monoalphabetic substitution keeps letter *frequencies*, just relabelled. The
chi-squared statistic compares a candidate's letter distribution to English's;
the lowest score is the most English-like. We use it to pick the right Caesar
shift automatically instead of eyeballing 26 lines.
"""
from ctfkit.encoding import rot

# Relative frequency (%) of letters in typical English text.
ENGLISH = {
    "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2, "g": 2.0,
    "h": 6.1, "i": 7.0, "j": 0.15, "k": 0.77, "l": 4.0, "m": 2.4, "n": 6.7,
    "o": 7.5, "p": 1.9, "q": 0.095, "r": 6.0, "s": 6.3, "t": 9.1, "u": 2.8,
    "v": 0.98, "w": 2.4, "x": 0.15, "y": 2.0, "z": 0.074,
}

CIPHERTEXT = "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"


def chi_squared(text: str) -> float:
    letters = [c for c in text.lower() if c.isalpha()]
    n = len(letters)
    score = 0.0
    for ch, pct in ENGLISH.items():
        expected = pct / 100 * n
        observed = letters.count(ch)
        if expected:
            score += (observed - expected) ** 2 / expected
    return score


def main() -> None:
    ranked = sorted(range(26), key=lambda k: chi_squared(rot(CIPHERTEXT, k)))
    best = ranked[0]
    print(f"best shift = {best}")
    print(f"plaintext  = {rot(CIPHERTEXT, best)}")


if __name__ == "__main__":
    main()
