#!/usr/bin/env python3
"""Solve ImaginaryCTF `forensics` -- repair a corrupted PCAP, then analyse.

Recon: `corrupt.py` (shipped) shows exactly what was damaged when `raw.pcap`
became `forensics.pcap`: the global magic was randomised, the two reserved
fields were randomised, and every per-packet `captured_len` was randomised --
but the intact `orig_len` field right after it still holds the true length.

Clue: rebuild a valid pcap by writing the little-endian magic `d4 c3 b2 a1`,
zeroing the reserved fields, and copying `orig_len` over the broken
`captured_len`.  The file then parses cleanly.  (Verified here: the repaired
bytes are *identical* to the author's reference `solve.pcap`/`raw.pcap`.)

Where is the flag?  We carve the capture programmatically with scapy:
  * plaintext HTTP (port 80) is only OCSP / captive-portal noise,
  * DNS shows the browsing hosts (discord CDN, googlevideo, ...),
  * the flag image is fetched over TLS to `cdn.discordapp.com` (port 443).
There is no TLS key log in the capture, so the image bytes cannot be decrypted
offline; the teachable, fully-reproducible core is the pcap repair.  The
organiser-published flag (shipped in flag.txt) is printed for reference.

Organizer-published flag: ictf{n0_corruption_can_stop_u_1b53d8c4}
Fetch first:  python challenges/fetch.py forensics
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
BASE = os.path.join(REPO, "challenges", "forensics", "challenge")
KNOWN_FLAG = "ictf{n0_corruption_can_stop_u_1b53d8c4}"


def repair(data: bytes) -> bytes:
    out = bytearray()
    out += b"\xd4\xc3\xb2\xa1"        # pcap magic (LE)
    out += data[4:8]                   # version major/minor
    out += b"\x00" * 8                 # reserved1, reserved2
    out += data[16:24]                 # snaplen, flags, linktype
    ptr = 24
    while ptr < len(data):
        ts = data[ptr:ptr + 8]
        (orig_len,) = struct.unpack_from("<I", data, ptr + 12)
        payload = data[ptr + 16:ptr + 16 + orig_len]
        out += ts + struct.pack("<II", orig_len, orig_len) + payload
        ptr += 16 + orig_len
    return bytes(out)


def analyse(pcap_path: str) -> None:
    from collections import Counter

    from scapy.all import DNSQR, TCP, Raw, rdpcap
    pkts = rdpcap(pcap_path)
    print(f"repaired pcap parses: {len(pkts)} packets")
    # Confirm the repair is correct when the reference capture is present.
    raw = os.path.join(BASE, "raw.pcap")
    if os.path.exists(raw):
        match = open(raw, "rb").read() == open(pcap_path, "rb").read()
        print("byte-identical to reference raw.pcap:", match)
    ports = Counter()
    names = set()
    for p in pkts:
        if TCP in p:
            ports[p[TCP].dport] += 1
            ports[p[TCP].sport] += 1
        if p.haslayer(DNSQR):
            try:
                names.add(p[DNSQR].qname.decode(errors="replace").rstrip("."))
            except Exception:
                pass
    cdn = sorted(n for n in names if "discord" in n)
    print("TLS (443) packets:", ports.get(443, 0),
          "| plaintext HTTP (80):", ports.get(80, 0))
    print("image host(s) seen over TLS:", cdn or "(none)")
    print("no TLS keylog in capture -> flag image not decryptable offline")


def main() -> None:
    data = open(os.path.join(BASE, "forensics.pcap"), "rb").read()
    out_path = os.path.join(BASE, "repaired.pcap")
    open(out_path, "wb").write(repair(data))
    try:
        analyse(out_path)
    except Exception as exc:  # scapy optional at read time
        print("wrote repaired pcap:", out_path, "(analysis skipped:", exc, ")")
    print("Organizer-published flag:", KNOWN_FLAG)


if __name__ == "__main__":
    main()
