#!/usr/bin/env python3
"""Obfuscation pattern: attribute names hidden behind getattr + string math.

Obfuscators avoid readable names. A common trick builds ``"system"`` and
``"os"`` from pieces and reaches them with ``getattr``/``__import__`` so the
words never appear as literals. The defence is the same every time: don't run
it, *read* it -- print the reconstructed strings.
"""
import dis

# A deliberately obfuscated call equivalent to: __import__("os").system("id")
parts = ["sy", "st", "em"]
mod = "".join([chr(c) for c in (111, 115)])   # "os"
attr = "".join(parts)                          # "system"
print("reconstructed module:", repr(mod))
print("reconstructed attr:  ", repr(attr))

# You could call getattr(__import__(mod), attr)(...). We only READ it here.
src = "getattr(__import__(m), a)"
print("--- what the obfuscated expression compiles to ---")
dis.dis(compile(src, "<obf>", "eval"))
