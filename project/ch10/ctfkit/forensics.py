"""Forensics helpers: file magic, LSB stego, and PCAP reassembly.

The first question in forensics is always "what *is* this file?" -- magic
bytes answer it. Then you carve, repair, or extract. This module gives you a
magic sniffer, an LSB bit-plane reader, and a TCP-stream reassembler built on
scapy.
"""
from __future__ import annotations

__all__ = [
    "MAGICS",
    "sniff_magic",
    "lsb_bits",
    "lsb_extract",
    "reassemble_tcp_streams",
]

# A few signatures worth memorising; value is a human label.
MAGICS = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
    b"PK\x03\x04": "ZIP / Office / JAR",
    b"\x1f\x8b": "gzip stream",
    b"BZh": "bzip2 stream",
    b"\x7fELF": "ELF executable",
    b"%PDF": "PDF document",
    b"\xd4\xc3\xb2\xa1": "pcap (little-endian, us)",
    b"\xa1\xb2\xc3\xd4": "pcap (big-endian, us)",
    b"\x0a\x0d\x0d\x0a": "pcapng",
    b"RIFF": "RIFF (WAV/AVI)",
    b"OggS": "Ogg stream",
}


def sniff_magic(data: bytes) -> str | None:
    """Return a label for ``data`` based on its leading magic bytes, or ``None``."""
    for sig, label in MAGICS.items():
        if data.startswith(sig):
            return label
    return None


def lsb_bits(values) -> bytes:
    """Pack a sequence of 0/1 bits (MSB-first) into bytes.

    LSB stego hides a message in the least-significant bit of each pixel
    channel; collect those bits in order and this reassembles the bytes.
    """
    bits = list(values)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | (b & 1)
        out.append(byte)
    return bytes(out)


def lsb_extract(image_path: str, channels: str = "RGB", plane: int = 0) -> bytes:
    """Extract an LSB-plane message from an image.

    Reads bit ``plane`` of each named channel, row-major, and packs the bits.
    Works for the common "flag in the low bit of every pixel" scheme; custom
    schemes need you to mirror their encoder (see the ``steganographic`` solve).
    """
    import numpy as np
    from PIL import Image

    img = Image.open(image_path).convert("RGB")
    arr = np.asarray(img).reshape(-1, 3)  # (pixels, RGB), row-major
    chan_index = {"R": 0, "G": 1, "B": 2}
    idxs = [chan_index[c] for c in channels]
    bits = ((arr[:, idxs] >> plane) & 1).reshape(-1)
    return lsb_bits(bits.tolist())


def reassemble_tcp_streams(pcap_path: str) -> dict:
    """Reassemble TCP payloads per flow from a pcap.

    Returns a dict mapping ``(src, sport, dst, dport)`` to the concatenated
    payload bytes, ordered by sequence number. Enough to read a file or
    command transferred over a plain TCP connection.
    """
    from scapy.all import rdpcap, TCP, IP

    packets = rdpcap(pcap_path)
    flows: dict = {}
    for pkt in packets:
        if TCP not in pkt or IP not in pkt:
            continue
        payload = bytes(pkt[TCP].payload)
        if not payload:
            continue
        key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        flows.setdefault(key, []).append((pkt[TCP].seq, payload))
    out = {}
    for key, chunks in flows.items():
        chunks.sort(key=lambda sp: sp[0])
        out[key] = b"".join(p for _, p in chunks)
    return out
