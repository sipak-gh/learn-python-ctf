#!/usr/bin/env python3
"""Reassemble a TCP stream from a pcap.

A single TCP conversation is split across many packets, possibly out of order.
`ctfkit.forensics.reassemble_tcp_streams` groups packets by flow and sorts them
by sequence number, giving you the bytes that crossed the wire -- enough to read
a transferred file, a command, or an HTTP body.

We synthesise a tiny capture with scapy (two out-of-order segments), write it,
then reassemble.
"""
import os

from scapy.all import IP, TCP, Raw, wrpcap

from ctfkit.forensics import reassemble_tcp_streams

SCRATCH = os.path.join(os.path.dirname(__file__), "_scratch")
os.makedirs(SCRATCH, exist_ok=True)
path = os.path.join(SCRATCH, "stream.pcap")

# One flow 10.0.0.1:1234 -> 10.0.0.2:80, two segments written out of order.
seg2 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, seq=110) / Raw(b"flag.txt HTTP/1.0\r\n")
seg1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, seq=100) / Raw(b"GET /secret_")
wrpcap(path, [seg2, seg1])  # deliberately reversed

flows = reassemble_tcp_streams(path)
for (src, sport, dst, dport), data in flows.items():
    print(f"{src}:{sport} -> {dst}:{dport}")
    print("  reassembled:", data)
