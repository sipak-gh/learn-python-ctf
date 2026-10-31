#!/usr/bin/env python3
"""A tiny local 'challenge' used by the pwntools example.

It asks for two numbers and prints their sum, then a goodbye line. Run on its
own it is interactive; the pwntools driver launches it with ``process()``.
"""
print("== adder service ==")
a = int(input("a> "))
b = int(input("b> "))
print("sum:", a + b)
print("bye")
