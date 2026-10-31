#!/usr/bin/env python3
"""Solve ImaginaryCTF `impossible` -- a leaked ``.pyc`` spills the secrets.

Recon: the published app ships `utils/crypto.py` whose comment brags that the
real FLAG_ENC/KEY/IV were changed on the server, so the source values are
fake. But `utils/__pycache__/crypto.cpython-310.pyc` was shipped too.

Clue: a `.pyc` is compiled from the REAL module that ran on the challenge
instance. Its constant pool still holds the true FLAG_ENC, KEY, and IV. No
decompiler needed -- we marshal-load the code object and read its string
constants (ctfkit.rev), then do the AES-CBC decrypt the source describes.

This only loads under Python 3.10 (the magic ties a .pyc to its interpreter) --
exactly why the course pins 3.10.

Fetch first:  python challenges/fetch.py impossible
"""
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from ctfkit.rev import find_strings, load_pyc

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PYC = os.path.join(
    REPO, "challenges", "impossible", "publish", "impossible",
    "app", "utils", "__pycache__", "crypto.cpython-310.pyc",
)


def main() -> None:
    code = load_pyc(open(PYC, "rb").read())
    # The three long hex strings are FLAG_ENC, KEY, IV, in source order.
    hexes = [s for s in find_strings(code)
             if len(s) >= 32 and all(c in "0123456789abcdef" for c in s)]
    flag_enc, key, iv = (bytes.fromhex(hexes[0]),
                         bytes.fromhex(hexes[1]),
                         bytes.fromhex(hexes[2]))
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    flag = unpad(cipher.decrypt(flag_enc), 32)
    print("FLAG:", flag.decode())


if __name__ == "__main__":
    main()
