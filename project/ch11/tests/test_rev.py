import marshal
import types

import pytest

from ctfkit import rev


def _sample_code():
    src = "def f(x):\n    secret = 'HARDCODED-SECRET'\n    return x + len(secret)\n"
    ns = {}
    exec(compile(src, "<sample>", "exec"), ns)
    return ns["f"].__code__


def test_find_strings_recurses_into_nested_code():
    code = compile(
        "def outer():\n    def inner():\n        return 'nested-flag'\n    return inner\n",
        "<m>",
        "exec",
    )
    assert "nested-flag" in rev.find_strings(code)


def test_load_marshal_roundtrip_and_disassemble():
    code = _sample_code()
    blob = marshal.dumps(code)
    restored = rev.load_marshal(blob)
    assert isinstance(restored, types.CodeType)
    assert "HARDCODED-SECRET" in rev.find_strings(restored)
    assert "LOAD_CONST" in rev.disassemble(restored)


def test_load_pyc_roundtrip_with_real_header():
    code = _sample_code()
    blob = rev.PYC_MAGIC_3_10 + b"\x00" * 12 + marshal.dumps(code)
    restored = rev.load_pyc(blob)
    assert "HARDCODED-SECRET" in rev.find_strings(restored)


def test_load_pyc_rejects_wrong_magic():
    with pytest.raises(ValueError):
        rev.load_pyc(b"\x00\x00\x00\x00" + b"\x00" * 12 + b"junk")
