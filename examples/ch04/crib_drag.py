#!/usr/bin/env python3
"""Crib dragging: recover a XOR key from a known piece of plaintext.

When you know (or guess) some plaintext that appears in a XOR ciphertext -- a
"crib" like a flag prefix ``lactf{`` or an HTTP header -- you can XOR it against
the ciphertext at that position to peel off the exact key bytes used there.
Drag a long enough crib and the key falls out directly; no brute force needed.

This is the engine behind the chapter's ``greek-cipher`` and
``one-more-time-pad`` solves.
"""
from ctfkit.encoding import xor

KEY = b"S3cr3tKey!!"
FLAG = b"lactf{crib_dragging_peels_the_key_right_off}"
CIPHERTEXT = xor(FLAG, KEY)          # repeating-key XOR


def drag(ciphertext: bytes, crib: bytes, offset: int) -> bytes:
    """Return the key bytes revealed by placing ``crib`` at ``offset``."""
    window = ciphertext[offset:offset + len(crib)]
    return xor(window, crib)


def main() -> None:
    # We know the flag starts with "lactf{" -- drag that crib at offset 0.
    revealed = drag(CIPHERTEXT, b"lactf{", 0)
    print("key bytes from crib:", revealed)       # == KEY[:6]

    # Knowing the 11-byte key length, one period of key decrypts everything.
    key = xor(CIPHERTEXT[:len(KEY)], FLAG[:len(KEY)])
    print("full key           :", key)
    print("recovered plaintext:", xor(CIPHERTEXT, key).decode())


if __name__ == "__main__":
    main()
