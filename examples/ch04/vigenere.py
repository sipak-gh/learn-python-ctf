#!/usr/bin/env python3
"""Vigenere cipher: a repeating-key Caesar, the letter-world cousin of XOR.

Vigenere shifts letter i by key letter i (the key repeats). Encryption adds the
key letter's position mod 26; decryption subtracts it. The weakness is the
same one every repeating-key cipher has: once you know (or guess) the key
length, each key position is a plain Caesar you can solve on its own. We meet
the byte version of this idea -- repeating-key XOR -- later in the chapter.
"""


def shift(text: str, key: str, sign: int) -> str:
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k = ord(key[ki % len(key)].lower()) - ord("a")
            out.append(chr((ord(ch) - base + sign * k) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def encrypt(text: str, key: str) -> str:
    return shift(text, key, +1)


def decrypt(text: str, key: str) -> str:
    return shift(text, key, -1)


def main() -> None:
    pt = "attack at dawn"
    key = "LEMON"
    ct = encrypt(pt, key)
    print("plaintext :", pt)
    print("key       :", key)
    print("ciphertext:", ct)
    print("decrypted :", decrypt(ct, key))


if __name__ == "__main__":
    main()
