import random

import pytest

from ctfkit import crypto as c


def test_single_byte_xor_break():
    pt = b"The quick brown fox jumps over the lazy dog and runs away."
    ct = c.single_byte_xor(pt, 0x5A)
    key, recovered, _ = c.break_single_byte_xor(ct)
    assert key == 0x5A
    assert recovered == pt


def test_repeating_key_xor_break():
    pt = (b"When in the course of human events it becomes necessary for one "
          b"people to dissolve the political bands which have connected them.")
    key = b"ICE"
    ct = c.single_byte_xor  # noqa: F841  (keep import usage obvious)
    from ctfkit.encoding import xor
    ct = xor(pt, key)
    found_key, recovered = c.break_repeating_key_xor(ct, keysize=3)
    assert found_key == key
    assert recovered == pt

