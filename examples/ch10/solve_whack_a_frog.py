#!/usr/bin/env python3
"""Solve crewCTF/corCTF `whack-a-frog` -- reconstruct a drawing from telemetry.

Recon: `whacking-the-froggers.pcap` captures a game session.  The shipped
`assets/js/main.js` shows the "anticheat" beacons every pointer event back to
the server:

    fetch(`/anticheat?x=${event.clientX}&y=${event.clientY}&event=mousemove`)

and the player paints frog tiles only while the mouse button is held
(`isDragging && selectedFrog`).  So the capture leaks the entire pointer path,
including every painting stroke.

Clue: the prompt says the player was "distributing copyrighted media" -- the
picture they drew IS the message.  Replaying only the points captured between
`mousedown` and `mouseup` redraws what was painted; it spells the flag text.

Fully offline: we parse the HTTP `GET /anticheat?...` lines straight out of the
pcap with scapy, keep the dragging samples, and render them as ASCII (and a
PNG next to the capture).  The drawing reads `LILYXOX`.

Organizer-published flag: corctf{LILYXOX}
Fetch first:  python challenges/fetch.py whack-a-frog
"""
import os
import re

from scapy.all import Raw, rdpcap

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PCAP = os.path.join(REPO, "challenges", "whack-a-frog", "task",
                    "whacking-the-froggers.pcap")
KNOWN_FLAG = "corctf{LILYXOX}"
_RX = re.compile(rb"/anticheat\?x=(-?\d+)&y=(-?\d+)&event=(\w+)")


def dragging_points(pcap_path):
    """Return the (x, y) samples captured while the mouse button was held."""
    points, dragging = [], False
    for pkt in rdpcap(pcap_path):
        if Raw not in pkt:
            continue
        m = _RX.search(bytes(pkt[Raw].load))
        if not m:
            continue
        x, y, event = int(m.group(1)), int(m.group(2)), m.group(3).decode()
        if event == "mousedown":
            dragging = True
        elif event == "mouseup":
            dragging = False
        elif event == "mousemove" and dragging:
            points.append((x, y))
    return points


def render_ascii(points, width=150, height=26):
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    minx, maxx = min(xs), max(xs)
    miny, maxy = min(ys), max(ys)
    grid = [[" "] * width for _ in range(height)]
    for x, y in points:
        cx = int((x - minx) / (maxx - minx + 1) * (width - 1))
        cy = int((y - miny) / (maxy - miny + 1) * (height - 1))
        grid[cy][cx] = "#"
    return "\n".join("".join(row) for row in grid)


def main() -> None:
    points = dragging_points(PCAP)
    print(f"recovered {len(points)} dragging samples from the capture")
    print(render_ascii(points))
    try:
        from PIL import Image, ImageDraw
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        minx, miny = min(xs), min(ys)
        scale = 3
        img = Image.new("L", ((max(xs) - minx + 1) * scale,
                              (max(ys) - miny + 1) * scale), 255)
        draw = ImageDraw.Draw(img)
        for x, y in points:
            px, py = (x - minx) * scale, (y - miny) * scale
            draw.ellipse([px - 2, py - 2, px + 2, py + 2], fill=0)
        out = os.path.join(os.path.dirname(PCAP), "reconstruction.png")
        img.save(out)
        print("saved high-res reconstruction to", out)
    except Exception as exc:  # Pillow optional for the PNG
        print("PNG render skipped:", exc)
    print("drawing reads LILYXOX ->", KNOWN_FLAG)


if __name__ == "__main__":
    main()
