#!/usr/bin/env python3
"""Solve DownUnderCTF 2023 `pyny` -- the source encoding IS the challenge.

Recon: the provided `pyny.py` starts with `#coding: punycode` and the rest is
unreadable. That declaration is the clue -- Python lets a source file name
*any* registered codec as its encoding, so the file is punycode-encoded text.

Decode it, and the decoded program checks the flag against
`'DUCTF{%s}' % python_warmup.__name__`. The function's name is spelled with
fancy Unicode letters that NFKC-normalise to `python_warmup`, which is what
`__name__` returns. So the flag is `DUCTF{python_warmup}`.

Fetch first:  python challenges/fetch.py pyny
"""
import os
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CHALL = os.path.join(REPO, "challenges", "pyny", "src", "pyny.py")


def main() -> None:
    raw = open(CHALL, "rb").read()
    # The codec name is the clue; strip the marker and decode the body.
    source = raw.replace(b"#coding: punycode", b"").decode("punycode")
    print("decoded source:\n" + source + "\n")

    # The check is: input == 'DUCTF{%s}' % python_warmup.__name__
    # Python normalises identifiers with NFKC, so the fancy-Unicode name
    # becomes the plain ASCII the interpreter actually sees.
    fancy_name = "ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ"
    name = unicodedata.normalize("NFKC", fancy_name)
    flag = "DUCTF{%s}" % name
    print("FLAG:", flag)


if __name__ == "__main__":
    main()
