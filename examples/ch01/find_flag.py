#!/usr/bin/env python3
"""Find flags by their format.

A flag looks like ``PREFIX{...}``: a short tag, braces, printable body. When
you have a blob of output and a flag is hiding in it, a regex for that shape
is the fastest way to spot it. This is the single most reused snippet in CTF.
"""
import re

# One or more letters/digits, then {...} with any non-brace, non-space bytes.
FLAG_RE = re.compile(rb"[A-Za-z0-9_]+\{[^}\s]*\}")

blob = b"""
log line 1: nothing here
debug: user=admin token=DUCTF{clu3s_l3ad_to_fl4gs}
log line 3: done
"""

for match in FLAG_RE.findall(blob):
    print("found:", match.decode())
