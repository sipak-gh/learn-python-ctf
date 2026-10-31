#!/usr/bin/env python3
"""XOR fundamentals: the one operation behind most CTF crypto.

Three facts make XOR the workhorse of CTF crypto:

* It is its own inverse: ``a ^ k ^ k == a``. Encrypt and decrypt are the same
  function.
* ``a ^ a == 0`` and ``a ^ 0 == a``.
* XORing two ciphertexts that share a key cancels the key: ``(p1^k) ^ (p2^k)
  == p1 ^ p2``. Key reuse leaks the XOR of the plaintexts.

In Python you XOR two ``int``s with ``^``; to XOR whole byte strings you zip
them. ``ctfkit.encoding.xor`` cycles the shorter operand so it doubles as a
repeating-key XOR.
"""
from ctfkit.encoding import xor


def main() -> None:
    a, k = 0x6C, 0x5A
    print(f"single byte:  {a:#04x} ^ {k:#04x} = {a ^ k:#04x}, "
          f"back = {a ^ k ^ k:#04x}")

    msg = b"flag{xor_is_reversible}"
    key = b"\x13"
    enc = xor(msg, key)              # key cycles over the message
    print("encrypted :", enc.hex())
    print("decrypted :", xor(enc, key))

    # Key reuse: two messages under the same key leak their XOR.
    p1, p2 = b"attack at dawn!!", b"defend till noon"
    k2 = b"SECRETKEYSECRETK"
    leak = xor(xor(p1, k2), xor(p2, k2))
    print("p1 ^ p2   :", leak)
    print("via direct:", xor(p1, p2))


if __name__ == "__main__":
    main()
