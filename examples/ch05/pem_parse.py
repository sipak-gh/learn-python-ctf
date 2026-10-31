#!/usr/bin/env python3
"""Parsing RSA keys: read a PEM with PyCryptodome and pull out n, e, d.

Challenges hand you keys as PEM/DER files, not Python integers. PyCryptodome's
``RSA.importKey`` parses either a public or a private key; the resulting object
exposes ``.n``, ``.e`` and (for private keys) ``.d``. We generate a key, write
it as PEM, then re-import it the way a solve script reads a challenge's
``private.pem`` -- the exact move behind this chapter's ``rsa`` solve.
"""
from Crypto.PublicKey import RSA


def main() -> None:
    key = RSA.generate(1024)
    pem = key.export_key()                 # PEM bytes, as shipped in a challenge
    print(pem.decode().splitlines()[0])    # -----BEGIN RSA PRIVATE KEY-----

    loaded = RSA.importKey(pem)
    print("n bits:", loaded.n.bit_length())
    print("e     :", loaded.e)
    print("has d :", hasattr(loaded, "d"))

    # Public half only: no private exponent.
    pub = RSA.importKey(key.publickey().export_key())
    print("public has_private:", pub.has_private())


if __name__ == "__main__":
    main()
