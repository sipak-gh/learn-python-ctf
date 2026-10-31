#!/usr/bin/env python3
"""Read a .pyc with ctfkit.rev: lift secrets without a decompiler.

We compile a module, write a real ``.pyc`` with
``importlib.util.source_to_cache`` semantics (here: header + marshal), then
reload it with :func:`ctfkit.rev.load_pyc` and pull its string constants with
:func:`ctfkit.rev.find_strings`. On a leaked challenge ``.pyc`` this is often
the whole solve -- the hardcoded key is sitting in the constant pool.
"""
import importlib.util
import marshal

from ctfkit.rev import disassemble, find_strings, load_pyc

SRC = (
    "KEY = 'sup3r_s3cr3t_k3y'\n"
    "def unlock(pin):\n"
    "    return 'FLAG{demo}' if pin == 1337 else 'nope'\n"
)
code = compile(SRC, "module.py", "exec")

# Build a .pyc image: 4-byte magic + 12 bytes of header + marshalled code.
pyc = importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal.dumps(code)

restored = load_pyc(pyc)
print("strings in the .pyc:", find_strings(restored))
print("--- disassembly (first lines) ---")
print("\n".join(disassemble(restored).splitlines()[:8]))
