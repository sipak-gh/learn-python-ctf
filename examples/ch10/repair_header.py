#!/usr/bin/env python3
"""Repair a corrupted file header with `struct`.

Forensics challenges love to smash a few header bytes so tools refuse the file.
The fix is not magic: read the format spec, then `struct.pack`/`unpack` the
fields back into shape. This is a miniature of the `forensics` challenge --
a tiny pcap whose magic and per-record length were scrambled.

pcap layout (little-endian):
  global header: magic(4) ver_major(2) ver_minor(2) res1(4) res2(4)
                 snaplen(4) linktype(4)
  each record:   ts_sec(4) ts_usec(4) captured_len(4) orig_len(4) data...
"""
import struct

from ctfkit.forensics import sniff_magic

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
payload = b"hello world"

# --- build a valid one-record pcap, then corrupt it like the challenge did ---
good = (
    PCAP_MAGIC
    + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)          # global header
    + struct.pack("<IIII", 0, 0, len(payload), len(payload))  # record header
    + payload
)
corrupt = bytearray(good)
corrupt[0:4] = b"\x13\x37\xbe\xef"           # magic randomised
struct.pack_into("<I", corrupt, 24, 999999)  # captured_len randomised (offset 24)

print("corrupted magic sniffs as:", sniff_magic(bytes(corrupt)))


def repair(data: bytes) -> bytes:
    out = bytearray(data)
    out[0:4] = PCAP_MAGIC                      # restore the magic
    (orig_len,) = struct.unpack_from("<I", out, 28)  # orig_len is intact
    struct.pack_into("<I", out, 24, orig_len)  # copy it over captured_len
    return bytes(out)


fixed = repair(bytes(corrupt))
print("repaired magic sniffs as:", sniff_magic(fixed))
print("repaired == original good file:", fixed == good)
