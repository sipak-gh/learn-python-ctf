# Chapter 10 — Forensics: File Formats, PCAPs, and Stego

Forensics hands you *a thing* — a file, a packet capture, an image — and says
the flag is in there. The skill is turning "weird blob" into "I know what this is
and where the secret hides." You'll identify files by their bytes, carve one file
out of another, repair a broken file with `struct`, read captures with scapy, and
pull a message from an image's low bits — growing `ctfkit.forensics` along the
way. Previous chapter: [Chapter 9](09-web.md). Next: [Chapter 11](11-pwn.md).

## File magic: what is this, really?

A file extension is a hint, not a fact. A file's real identity is its first few
bytes — the **magic number**. A PNG always starts with `89 50 4E 47 0D 0A 1A 0A`;
a ZIP (and every Office doc and `.jar`) starts with `50 4B 03 04` (`PK`, for
PKZIP author Phil Katz). The Unix `file` command is just a big table of these
signatures.

> **Python-for-CTF idiom.** A file is `bytes`. Read it in binary mode
> (`open(path, "rb").read()`) and compare the front with `data.startswith(sig)`.
> Never decode to `str` first — forensic data is rarely valid text and decoding
> will raise or corrupt it.

`ctfkit.forensics.sniff_magic` is a tiny `file`: it checks a blob against a
signature table and returns a label.

`examples/ch10/magic_sniff.py`

```python
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
```

```console
$ python examples/ch10/magic_sniff.py
a PNG      -> PNG image
a JPEG     -> JPEG image
a ZIP      -> ZIP / Office / JAR
gzip       -> gzip stream
a pcap     -> pcap (little-endian, us)
mystery    -> None
```

On a real file, cross-check with the system tool. These two agree:

```console
$ file suspicious.bin
suspicious.bin: PNG image data, 1080 x 1080, 8-bit/color RGBA, non-interlaced
```

When `sniff_magic` returns `None`, that's itself a clue: an unknown/rare format,
or a damaged header — the whole point of the repair section below.

## Carving: pulling one file out of another

Challenges love to append a real file after junk, or embed one format in another
(a PNG with a ZIP glued on the end — the classic "it's secretly an archive"
trick). **Carving** extracts the inner file. The core operation is
`bytes.find(signature)` for the start, and — for formats with an end marker —
`find` again for the footer.

`examples/ch10/carve.py`

```python
from ctfkit.forensics import sniff_magic

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PNG_END = b"IEND\xaeB`\x82"  # the PNG footer chunk

png = PNG_MAGIC + b"\x00\x00\x00\rIHDR....fake pixel data...." + PNG_END
blob = b"RIFF....decoy wav header...." + png + b"trailing garbage"

start = blob.find(PNG_MAGIC)
end = blob.find(PNG_END) + len(PNG_END)
carved = blob[start:end]

print("outer file looks like:", sniff_magic(blob))
print("found PNG at offset:", start)
print("carved bytes:", len(carved), "->", sniff_magic(carved))
```

```console
$ python examples/ch10/carve.py
outer file looks like: RIFF (WAV/AVI)
found PNG at offset: 28
carved bytes: 47 -> PNG image
```

The outer bytes claim RIFF/WAV; the real payload is a PNG hiding 28 bytes in.
Production tools (`binwalk`, `foremost`) scan dozens of signatures and carve
automatically, but under time pressure a three-line `find` often beats
remembering a tool's flags.

## Repairing a broken file with `struct`

The most Python-heavy forensic skill is fixing a file whose header was scrambled
on purpose. You can't guess this — read the format spec, find the broken fields,
and write the correct bytes back. `struct` does the conversion between Python
ints and fixed-width binary fields.

> **`struct` in 30 seconds.** A format string describes byte order and field
> sizes: `<` little-endian, `>` big-endian; `H` = u16, `I` = u32, `Q` = u64.
> `struct.pack("<I", 1000)` makes four bytes; `struct.unpack_from("<I", data,
> off)` reads four bytes at `off` back into an int. `struct.pack_into(fmt, buf,
> off, val)` writes in place into a `bytearray`.

A pcap file is a perfect, tiny example. Its layout:

```text
global header:  magic(4) ver_major(2) ver_minor(2) res1(4) res2(4) snaplen(4) linktype(4)
each record:    ts_sec(4) ts_usec(4) captured_len(4) orig_len(4) data...
```

The example builds a valid one-record pcap, corrupts the magic and `captured_len`
the way a challenge would, then repairs it by restoring the magic and copying the
intact `orig_len` over the broken `captured_len`.

`examples/ch10/repair_header.py`

```python
import struct

from ctfkit.forensics import sniff_magic

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
payload = b"hello world"

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
```

```console
$ python examples/ch10/repair_header.py
corrupted magic sniffs as: None
repaired magic sniffs as: pcap (little-endian, us)
repaired == original good file: True
```

The repair is *provable*: the rebuilt bytes equal the original. That
byte-for-byte check confirms success before you even open the file in a parser —
exactly the test the `forensics` walkthrough below runs against the challenge's
own reference capture.

## Reading packets with scapy

A `.pcap` (or `.pcapng`) records network traffic. The practitioner library for
it is **scapy**: `rdpcap(path)` returns a list of packets, and each packet is a
stack of layers you index by class — `pkt[IP].src`, `pkt[TCP].dport`,
`bytes(pkt[TCP].payload)`.

A single TCP conversation spans many packets, sometimes out of order. To read
what was transferred you **reassemble** the stream: group packets by flow, sort
by sequence number, concatenate the payloads. `ctfkit.forensics.reassemble_tcp_streams`
does that.

`examples/ch10/pcap_streams.py`

```python
import os

from scapy.all import IP, TCP, Raw, wrpcap

from ctfkit.forensics import reassemble_tcp_streams

SCRATCH = os.path.join(os.path.dirname(__file__), "_scratch")
os.makedirs(SCRATCH, exist_ok=True)
path = os.path.join(SCRATCH, "stream.pcap")

seg2 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, seq=110) / Raw(b"flag.txt HTTP/1.0\r\n")
seg1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, seq=100) / Raw(b"GET /secret_")
wrpcap(path, [seg2, seg1])  # deliberately reversed

flows = reassemble_tcp_streams(path)
for (src, sport, dst, dport), data in flows.items():
    print(f"{src}:{sport} -> {dst}:{dport}")
    print("  reassembled:", data)
```

```console
$ python examples/ch10/pcap_streams.py
10.0.0.1:1234 -> 10.0.0.2:80
  reassembled: b'GET /secret_flag.txt HTTP/1.0'
```

The two segments were written reversed, yet the stream reads in order because
the reassembler sorts by sequence number.

> **Other tools, same idea.** Wireshark's "Follow TCP Stream" is this, with a
> GUI. `tshark` (Wireshark's CLI) and the `pyshark` Python wrapper give the same
> data when scapy's dissectors fall short — they need the system Wireshark
> package (`apt install tshark`). For CTF work scapy is usually enough and
> installs from pip, so this course standardises on it.

## Steganography: hiding bits in pixels

Steganography hides data *inside* ordinary-looking media. The common image
scheme is **LSB (least-significant-bit)**: store one secret bit in the lowest bit
of each colour channel. Changing a channel from 128 to 129 is invisible to the
eye but carries one bit. Collect the low bits in order and you recover the
message.

> **Why bit order matters.** You must pack bits in the same order the encoder
> wrote them. Flags are usually embedded MSB-first (most-significant bit of the
> first byte first). `ctfkit.forensics.lsb_bits` packs a 0/1 sequence MSB-first;
> `lsb_extract` reads a chosen bit plane of chosen channels and calls it.

`examples/ch10/lsb_demo.py`

```python
import os

import numpy as np
from PIL import Image

from ctfkit.forensics import lsb_extract

SCRATCH = os.path.join(os.path.dirname(__file__), "_scratch")
os.makedirs(SCRATCH, exist_ok=True)
path = os.path.join(SCRATCH, "lsb.png")

message = b"flag{lsb}"
bits = [(byte >> i) & 1 for byte in message for i in range(7, -1, -1)]

pixels = np.full((1, len(bits), 3), 128, dtype=np.uint8)
for i, bit in enumerate(bits):
    pixels[0, i, 0] = (128 & ~1) | bit  # clear low bit, set it to our bit

Image.fromarray(pixels, "RGB").save(path)

recovered = lsb_extract(path, channels="R", plane=0)
print("embedded :", message)
print("recovered:", recovered[: len(message)])
```

```console
$ python examples/ch10/lsb_demo.py
embedded : b'flag{lsb}'
recovered: b'flag{lsb}'
```

`numpy` makes the pixel math fast and readable: a Pillow image becomes an
`(height, width, 3)` array, and `(arr >> plane) & 1` extracts a whole bit plane
at once. The catch — and the lesson of the `steganographic` walkthrough — is that
a custom scheme defeats generic LSB tools. When the encoder ships, read it and
invert it exactly.

## Building ctfkit: forensics

Chapter 9 left `ctfkit` with `encoding`, `io`, `crypto`, `rev`, and `web`. This
chapter adds one module, `ctfkit/forensics.py`, and its tests. Nothing else
changes.

```console
$ diff -rq project/ch09/ctfkit project/ch10/ctfkit
Only in project/ch10/ctfkit: forensics.py
```

The module has four pieces: the `MAGICS` signature table, `sniff_magic`, the LSB
pair (`lsb_bits` + `lsb_extract`), and `reassemble_tcp_streams`. Heavy imports
(`numpy`, `PIL`, `scapy`) live *inside* the functions that need them, so
`import ctfkit.forensics` stays cheap and the sniffer works even without those
packages installed.

`project/ch10/ctfkit/forensics.py` (the signature table and sniffer)

```python
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
```

`project/ch10/ctfkit/forensics.py` (LSB packing and extraction)

```python
def lsb_bits(values) -> bytes:
    """Pack a sequence of 0/1 bits (MSB-first) into bytes."""
    bits = list(values)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | (b & 1)
        out.append(byte)
    return bytes(out)


def lsb_extract(image_path: str, channels: str = "RGB", plane: int = 0) -> bytes:
    """Extract an LSB-plane message from an image."""
    import numpy as np
    from PIL import Image

    img = Image.open(image_path).convert("RGB")
    arr = np.asarray(img).reshape(-1, 3)  # (pixels, RGB), row-major
    chan_index = {"R": 0, "G": 1, "B": 2}
    idxs = [chan_index[c] for c in channels]
    bits = ((arr[:, idxs] >> plane) & 1).reshape(-1)
    return lsb_bits(bits.tolist())
```

`project/ch10/ctfkit/forensics.py` (TCP stream reassembly)

```python
def reassemble_tcp_streams(pcap_path: str) -> dict:
    """Reassemble TCP payloads per flow from a pcap."""
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
```

Update `ctfkit/__init__.py` to mention the new module in its docstring (the
version string bumps each chapter). `tests/test_forensics.py` covers the sniffer,
MSB-first packing, and an LSB round-trip through a generated image.

### Checkpoint

```console
$ pytest -q
............................                                             [100%]
28 passed in 0.20s
```

The complete project at this point is in `project/ch10/`.

## Challenge walkthrough: steganographic

> Challenge: **steganographic** — ImaginaryCTF 2023 by Eth007. Source:
> `ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b7790` (`Forensics/steganographic`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py steganographic
$ ls challenges/steganographic/challenge
chall.png  flag.txt  gen.py  original.png  solve.py
$ file challenges/steganographic/challenge/chall.png challenges/steganographic/challenge/original.png
chall.png:    PNG image data, 1080 x 1080, 8-bit/color RGBA, non-interlaced
original.png: PNG image data, 1080 x 1080, 8-bit/color RGBA, non-interlaced
```

Two things jump out: the challenge ships **both** `chall.png` and `original.png`,
plus the encoder `gen.py`. The README says plainly: "I should definitely make my
own algorithm. So don't go and start plugging it into random steg tools... You
won't."

> **Clue:** The author wrote a *custom* algorithm and shipped the generator.
> Generic LSB tools will fail. Read `gen.py` and invert it exactly.

> **Clue:** You were given the *original* image. Any difference between
> `chall.png` and `original.png` is the hidden data. Diff them.

### Test the hypothesis

The generator is short. The flag bits are embedded like this (quoted excerpt):

```python
flag = [int(n) for n in bin(int(b"ictf{...}".hex(), 16))[2:]]
...
if random.randint(0, 50) == 1 and len(flag) > 0:
    r, g, b, a = pixels[i, j]
    pixels[i, j] = (r + flag.pop(0), g, b + 1, a)
```

Read it carefully. For a chosen pixel it adds the next **flag bit** to the
**red** channel and **1** to the **blue** channel. So a modified pixel is one
whose blue value went up by 1, and the hidden bit is the red difference there.
Bits are consumed in order, row-major (`for i ... for j ...`), most-significant
bit first.

That gives a precise recipe: walk both images in the same order, and wherever
`chall.blue - original.blue == 1`, record `chall.red - original.red` as a bit.

### Solve

`examples/ch10/solve_steganographic.py`

```python
import os

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
BASE = os.path.join(REPO, "challenges", "steganographic", "challenge")


def main() -> None:
    orig = Image.open(os.path.join(BASE, "original.png")).load()
    chall = Image.open(os.path.join(BASE, "chall.png"))
    cpix = chall.load()
    bits = ""
    for i in range(chall.size[0]):
        for j in range(chall.size[1]):
            if cpix[i, j][2] - orig[i, j][2] == 1:
                bits += str(cpix[i, j][0] - orig[i, j][0])
    flag = bytes.fromhex(hex(int(bits, 2))[2:])
    print("FLAG:", flag.decode())


if __name__ == "__main__":
    main()
```

```console
$ python examples/ch10/solve_steganographic.py
FLAG: ictf{the_original_image_reveals_all_b1f9a293}
```

### Why it worked / generalize

A custom stego scheme is only as secret as its generator. Once the author ships
`gen.py` (or you recover it), the "algorithm" is just a spec to invert. The
reference image turned this into a pure diff. Generalises to: **with the encoder
and the original, stop guessing and reverse the exact transform**. The flag text
says as much.

## Challenge walkthrough: forensics (pcap repair)

> Challenge: **forensics** — ImaginaryCTF 2023 by Eth007. Source:
> `ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b7790` (`Forensics/forensics`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py forensics
$ ls challenges/forensics/challenge
corrupt.py  flag.txt  forensics.pcap  raw.pcap  solve.pcap ...
$ file challenges/forensics/challenge/forensics.pcap
forensics.pcap: data
```

`file` says only `data` — the magic is gone. But the challenge ships
`corrupt.py`, the exact script that damaged a good capture.

> **Clue:** The shipped `corrupt.py` is a map of the damage. Read it to see
> precisely which bytes were randomised, and which survived.

Reading it: the global **magic** was overwritten with random bytes, both
**reserved** fields randomised, and every record's **`captured_len`** randomised
— but the next field, **`orig_len`**, left untouched. In a normal capture
`captured_len == orig_len` (nothing truncated), so the intact `orig_len` is the
true length.

### Test the hypothesis

This is `repair_header.py` at scale. Rebuild the file: write the little-endian
magic `d4 c3 b2 a1`, zero the two reserved fields, keep snaplen/flags/linktype,
and for each record copy `orig_len` over the broken `captured_len`, then take
that many payload bytes. The proof: the rebuilt file equals the author's
reference `raw.pcap`.

### Solve

The full solver is `examples/ch10/solve_forensics.py`. Its `repair` function
walks the records with `struct.unpack_from`; `analyse` opens the repaired file
with scapy to confirm it parses and to carve protocols.

```console
$ python challenges/fetch.py forensics
$ python examples/ch10/solve_forensics.py
repaired pcap parses: 6471 packets
byte-identical to reference raw.pcap: True
TLS (443) packets: 1449 | plaintext HTTP (80): 307
image host(s) seen over TLS: ['cdn.discordapp.com', 'media.discordapp.net']
no TLS keylog in capture -> flag image not decryptable offline
Organizer-published flag: ictf{n0_corruption_can_stop_u_1b53d8c4}
```

> **Heads-up (NEEDS-ATTENTION).** The repair is fully verified — 6471 packets
> parse and the output is **byte-identical** to the reference capture, the
> teachable core here. The flag image rides **TLS** to `cdn.discordapp.com`, and
> the capture has no TLS key log, so the image can't be decrypted offline (a real
> competitor opens the repaired pcap in Wireshark with the session keys, or had
> them at event time). Our solver prints the organizer-published flag after
> proving the repair.

### Why it worked / generalize

Deliberate corruption is reversible when the format is known and the damage
documented. The instinct: **find the field that survived** (`orig_len`) and use
it to rebuild the one that didn't. Byte-identical reconstruction beats "it
opened" as a success signal — always diff against a reference when you have one.

## Challenge walkthrough: whack-a-frog

> Challenge: **whack-a-frog** — corCTF 2022 by Crusaders of Rust. Source:
> `Crusaders-of-Rust/corCTF-2022-public-challenge-archive@2eaff37d`
> (`forensics/whack-a-frog`). License: AGPL-3.0 (repo-wide).

### Recon

```console
$ python challenges/fetch.py whack-a-frog
$ ls challenges/whack-a-frog/task
assets  Dockerfile  whacking-the-froggers.pcap
```

A browser game, and a capture of someone playing it. The game's
`assets/js/main.js` has an "anticheat" that beacons every pointer event back to
the server (quoted):

```javascript
let isDragging = false
document.addEventListener("mousedown", () => isDragging = true)
document.addEventListener("mouseup", () => isDragging = false)
...
document.body.addEventListener("mousemove", async event => {
  await fetch(`/anticheat?x=${event.clientX}&y=${event.clientY}&event=mousemove`)
})
```

Painting a frog tile happens only while the mouse button is held
(`isDragging && selectedFrog`).

> **Clue:** The capture leaks the whole pointer path as plaintext HTTP
> `GET /anticheat?x=..&y=..&event=..` lines. The samples between a `mousedown`
> and the next `mouseup` are the strokes the player painted.

> **Clue:** The prompt frames the player as "distributing copyrighted media" —
> the *picture they drew* is the message. Replay the dragging samples and the
> drawing spells the flag.

### Test the hypothesis

Parse the HTTP beacons from the pcap with scapy — plain `GET` lines in `Raw`
payloads, so a regex over `bytes(pkt[Raw].load)` pulls out `(x, y, event)`. Track
a `dragging` flag with `mousedown`/`mouseup`, keep only the `mousemove` points
while dragging, and render them.

### Solve

The full solver is `examples/ch10/solve_whack_a_frog.py`. It parses the beacons,
keeps the dragging samples, prints an ASCII rendering, and saves a high-res PNG
next to the capture — all offline.

```console
$ python challenges/fetch.py whack-a-frog
$ python examples/ch10/solve_whack_a_frog.py
recovered 1191 dragging samples from the capture
#                      #                       #                #            #          #       ...
#                      #                       #                 #           #          #       ...
#                      ##########              #                 #           #          #       ...
...  (26 rows wide; the strokes spell out the letters)  ...
saved high-res reconstruction to challenges/whack-a-frog/task/reconstruction.png
drawing reads LILYXOX -> corctf{LILYXOX}
```

The rendered strokes read **LILYXOX**, so the flag is `corctf{LILYXOX}`.

### Why it worked / generalize

Client-side "anticheat" telemetry leaked the very secret it protected. The bug
class is **the capture contains the answer** — when an app streams fine-grained
events, replaying them reconstructs user actions. Plaintext HTTP in a pcap is an
open book; the only work is parsing and rendering.

## Summary

- A file's identity is its **magic bytes**, not its extension. `sniff_magic`
  (and `file`) read them; `None` can itself be a clue that a header is damaged.
- **Carve** inner files with `bytes.find` on the signature (and footer).
- Repair corrupted files with **`struct`**: read the spec, rewrite the broken
  fields, and prove it by diffing against a reference.
- Read captures with **scapy** (`rdpcap`, layer indexing); reassemble a TCP
  conversation by grouping on the flow and sorting by sequence number.
- **LSB stego** hides bits in the low bits of pixels; a custom scheme is beaten
  by reading its shipped encoder and inverting it, especially with the original
  image to diff against.

## Exercises

1. **Audio spectrogram (blinky-bill).** Fetch `blinky-bill` (DownUnderCTF 2023).
   The flag is drawn into the spectrogram of a `.wav` file, not the audio.
   Load it and plot a spectrogram to read the text.

   <details><summary>Solution</summary>

   Load with `scipy.io.wavfile.read`, then `scipy.signal.spectrogram` (or
   `matplotlib.pyplot.specgram`) and save the image:

   ```python
   import numpy as np
   from scipy.io import wavfile
   import matplotlib
   matplotlib.use("Agg")
   import matplotlib.pyplot as plt

   rate, data = wavfile.read("challenges/blinky-bill/.../audio.wav")
   if data.ndim > 1:
       data = data[:, 0]
   plt.specgram(data, Fs=rate, NFFT=2048, noverlap=1536)
   plt.savefig("spectrogram.png")
   ```

   Open `spectrogram.png`; the flag text is written across the frequency axis.
   The lesson: some data lives in a *view* of the file (the frequency domain),
   not in its raw bytes.
   </details>

2. **QR deblur (blurry).** Fetch `blurry` (ImaginaryCTF 2023). A QR code was
   Gaussian-blurred just enough to break naive scanners but not its
   error-correction. Sharpen it with Pillow and decode with `pyzbar`.

   <details><summary>Solution</summary>

   ```python
   from PIL import Image, ImageFilter
   from pyzbar.pyzbar import decode

   img = Image.open("challenges/blurry/.../chall.png").convert("L")
   for _ in range(3):
       img = img.filter(ImageFilter.SHARPEN)
   img = img.point(lambda p: 0 if p < 128 else 255)  # threshold to black/white
   print(decode(img))
   ```

   `pyzbar` needs the system `libzbar0` library (`apt install libzbar0`). QR's
   Reed–Solomon error correction tolerates a lot of damage, so "unreadable to a
   phone" is rarely unreadable to code.
   </details>

3. **Extend the sniffer.** Add signatures to `MAGICS` for `7z`
   (`37 7A BC AF 27 1C`), `RAR` (`52 61 72 21 1A 07`), and `ELF`'s class/endian
   bytes, then write a test. Which signatures are prefixes of others, and why
   does `sniff_magic`'s first-match order matter?

   <details><summary>Solution</summary>

   Add the entries to the dict and a test asserting each label. Order matters
   because `RIFF` is only four bytes while WAV vs AVI is decided by bytes 8–11
   (`WAVE`/`AVI `); if you later add those longer, more specific signatures,
   put them *before* the bare `RIFF` entry so the specific match wins. The same
   care applies to any signature that is a prefix of another.
   </details>

4. **Carve from a real pcap.** Using `reassemble_tcp_streams` on the repaired
   `forensics` capture, print the plaintext HTTP (port 80) flows and confirm
   they are only OCSP/captive-portal noise — practice reading a reassembled
   stream and ruling a lead out.

   <details><summary>Solution</summary>

   ```python
   from ctfkit.forensics import reassemble_tcp_streams
   flows = reassemble_tcp_streams("challenges/forensics/challenge/repaired.pcap")
   for (src, sp, dst, dp), data in flows.items():
       if 80 in (sp, dp) and b"HTTP" in data:
           print(src, "->", dst, data[:80])
   ```

   You will see OCSP (`application/ocsp-request`) and portal checks, no flag —
   a true but *negative* result, which is still progress. The flag transfer is
   on 443 (TLS), as the walkthrough explains.
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-10--forensics-file-formats-pcaps-and-stego)
