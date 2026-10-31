import pytest

from ctfkit import encoding as e


def test_xor_roundtrip_and_cycle():
    key = b"KEY"
    ct = e.xor(b"hello world", key)
    assert e.xor(ct, key) == b"hello world"
    # cycles the key
    assert e.xor(b"\x00\x00\x00\x00", b"\x01\x02") == b"\x01\x02\x01\x02"


def test_hex_and_base64_tolerate_sloppy_input():
    assert e.from_hex("de ad\nbe ef") == bytes.fromhex("deadbeef")
    # missing padding is restored
    assert e.b64d("aGVsbG8") == b"hello"
    assert e.b64e(b"hello") == b"aGVsbG8="


def test_rot_and_rot13():
    assert e.rot("abcXYZ", 1) == "bcdYZA"
    assert e.rot13("Hello") == "Uryyb"
    assert e.rot13(e.rot13("Hello")) == "Hello"


def test_long_bytes_roundtrip():
    for n in (1, 255, 256, 65535, 1 << 200):
        assert e.bytes_to_long(e.long_to_bytes(n)) == n


def test_printable_ratio():
    assert e.printable_ratio(b"hello") == 1.0
    assert e.printable_ratio(b"\x00\x01\x02\x03") == 0.0
