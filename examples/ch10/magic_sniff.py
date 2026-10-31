#!/usr/bin/env python3
"""Identify files by their leading magic bytes.

The extension lies; the first few bytes don't. `ctfkit.forensics.sniff_magic`
checks a blob against a table of signatures -- the same idea the Unix `file`
command uses, just small enough to read.
"""
from ctfkit.forensics import sniff_magic

samples = {
    "a PNG":   b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    "a JPEG":  b"\xff\xd8\xff\xe0\x00\x10JFIF",
    "a ZIP":   b"PK\x03\x04\x14\x00\x00\x00",
    "gzip":    b"\x1f\x8b\x08\x00",
    "a pcap":  b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00",
    "mystery": b"hello, this is just text",
}

for name, blob in samples.items():
    print(f"{name:10} -> {sniff_magic(blob)}")
