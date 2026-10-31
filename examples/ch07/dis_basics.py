#!/usr/bin/env python3
"""Disassemble a small function and read its code object.

Every Python function carries a *code object* (``__code__``) holding the
compiled bytecode plus the tables the VM needs: constants (``co_consts``),
names it touches (``co_names``), and the raw instruction stream. You can read
all of this without running the function -- the heart of Python reversing.
"""
import dis


def check(pin):
    secret = "p1n_1s_1337"
    return pin == secret


code = check.__code__
print("co_consts:", code.co_consts)
print("co_names: ", code.co_names)
print("co_varnames:", code.co_varnames)
print("--- disassembly ---")
dis.dis(check)
