#!/usr/bin/env python3
"""Blacklist bypass: rebuild banned names so the literal never appears.

A jail that bans the substrings ``os``, ``system``, ``flag`` scans your
*source text*. Build those strings at runtime from ``chr()`` and the filter
never sees them; ``getattr`` then reaches the attribute whose name you
assembled. We run a tiny local "jail" to make the bypass concrete.
"""
BANNED = ["os", "system", "flag"]


def jail(code: str):
    if any(bad in code for bad in BANNED):
        raise ValueError("blacklisted token")
    return eval(code)  # the jail still eval()s whatever passes the filter


# Direct attempt is blocked -- the literal 'os'/'system' is right there.
blocked = "__import__('os').system"
try:
    jail(blocked)
except ValueError as e:
    print("blocked:", blocked, "->", e)

# Bypass: 'os' = chr(111)+chr(115), 'system' = chr(115)+'ystem'. No banned
# substring appears, so the filter passes it -- and it resolves to the real
# os.system function object (we fetch it, we don't run a command).
payload = "getattr(__import__(chr(111)+chr(115)), chr(115)+'ystem')"
print("payload passes filter:", not any(b in payload for b in BANNED))
resolved = jail(payload)
print("resolved to:", resolved)
print("is os.system:", resolved is __import__("os").system)
