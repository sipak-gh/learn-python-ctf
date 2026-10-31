#!/usr/bin/env python3
"""ROT13, Caesar shifts, and URL percent-encoding.

* ROT13 rotates letters by 13; applying it twice restores the text.
* A Caesar cipher is the same idea with any shift.
* URL/percent-encoding escapes bytes as ``%XX`` so they survive a URL.
"""
import codecs
import urllib.parse

from ctfkit.encoding import rot, rot13, url_encode, url_decode

# ROT13 via the stdlib codec, and via ctfkit (same result).
print("codecs rot13:", codecs.encode("Hello", "rot13"))
print("ctfkit rot13:", rot13("Hello"))
print("twice       :", rot13(rot13("Hello")))

# Any shift; ctfkit.rot leaves digits and symbols alone.
print("shift 3:", rot("abcXYZ 123", 3))

# Percent-encoding. A space, a brace, and a non-ASCII byte all get escaped.
s = "flag={a b}"
enc = url_encode(s)
print("url_encode:", enc)
print("url_decode:", url_decode(enc))

# The stdlib equivalents you'll see in writeups.
print("quote     :", urllib.parse.quote(s, safe=""))
