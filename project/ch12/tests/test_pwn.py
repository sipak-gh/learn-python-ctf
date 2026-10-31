import struct

import pytest

from ctfkit import pwn


def test_pack_unpack_roundtrip():
    assert pwn.u64(pwn.p64(0xDEADBEEFCAFEBABE)) == 0xDEADBEEFCAFEBABE
    assert pwn.u32(pwn.p32(0xCAFEBABE)) == 0xCAFEBABE
    # short leaks are NUL-padded
    assert pwn.u64(b"\x41\x42\x43") == 0x434241


def test_cyclic_unique_windows_and_find():
    pattern = pwn.cyclic(256)
    assert len(pattern) == 256
    offset = 40
    window = pattern[offset : offset + 4]
    assert pwn.cyclic_find(window) == offset
    # int form (little-endian) agrees
    val = int.from_bytes(window, "little")
    assert pwn.cyclic_find(val) == offset


def test_flat_builds_padded_payload():
    payload = pwn.flat(b"A" * 8, 0xDEADBEEF, length=24, filler=b"\x90")
    assert payload[:8] == b"A" * 8
    assert payload[8:16] == pwn.p64(0xDEADBEEF)
    assert payload[16:] == b"\x90" * 8
    assert len(payload) == 24


def test_libc_base_and_resolve():
    base = 0x7F0000000000
    sym_off = 0x50D60
    leak = base + sym_off
    assert pwn.libc_base(leak, sym_off) == base
    assert pwn.resolve(base, 0x1234) == base + 0x1234


def test_libc_base_rejects_unaligned():
    with pytest.raises(ValueError):
        pwn.libc_base(0x7F0000001234, 0x1111)
