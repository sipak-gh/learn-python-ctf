#!/usr/bin/env python3
"""Break single-byte XOR by trying all 256 keys and scoring for English.

A single-byte XOR key has only 256 possibilities. Decrypt with each, score how
"English" the result looks, and keep the best. ``ctfkit.crypto`` does exactly
this; here we call it and also show the raw ranking so you can see why the
winner wins.
"""
from ctfkit.crypto import break_single_byte_xor, single_byte_xor

# "Cooking MC's like a pound of bacon" XORed with 0x58 (the classic example).
CIPHERTEXT = bytes.fromhex(
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
)


def main() -> None:
    key, plaintext, score = break_single_byte_xor(CIPHERTEXT)
    print(f"key  = {key:#04x} ({key!r})")
    print(f"text = {plaintext.decode()}")
    print(f"score= {score:.3f}")

    # Sanity check: re-encrypting with the key returns the ciphertext.
    assert single_byte_xor(plaintext, key) == CIPHERTEXT
    print("round-trip OK")


if __name__ == "__main__":
    main()
