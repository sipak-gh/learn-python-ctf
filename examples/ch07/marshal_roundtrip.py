#!/usr/bin/env python3
"""marshal: serialise a code object, then load and run it back.

``.pyc`` files store a code object with :mod:`marshal`, Python's internal
object serialiser. ``marshal`` is not stable across Python versions (that is
*why* a ``.pyc`` is tied to one interpreter), but within one version you can
round-trip a code object, inspect it, and ``exec`` it.
"""
import marshal

src = "def greet(name):\n    return 'hello ' + name\n"
code = compile(src, "<demo>", "exec")

blob = marshal.dumps(code)            # bytes you could write into a .pyc body
print("marshalled bytes:", len(blob))

restored = marshal.loads(blob)        # same code object, no source needed
ns = {}
exec(restored, ns)                    # define greet() in ns
print(ns["greet"]("ctf"))
print("nested consts:", [c for c in restored.co_consts])
