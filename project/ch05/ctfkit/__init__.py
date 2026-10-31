"""ctfkit -- a small, readable toolkit for solving CTF challenges.

The package grows one module per chapter of *Learn Python for CTFs*:

* :mod:`ctfkit.encoding`   -- hex / base64 / url / rot / xor byte wrangling (ch02)
* :mod:`ctfkit.io`         -- socket and pwntools service wrappers           (ch03)
* :mod:`ctfkit.crypto`     -- xor breaking, RSA helpers, PRNG recovery       (ch04-06)
* :mod:`ctfkit.rev`        -- .pyc / marshal / dis reversing helpers          (ch07)
* :mod:`ctfkit.web`        -- SSTI probes and pickle RCE builders             (ch08-09)
* :mod:`ctfkit.forensics`  -- file magic, LSB stego, pcap reassembly          (ch10)
* :mod:`ctfkit.pwn`        -- cyclic offsets, flat payloads, leak math        (ch11)

Everything is deliberately small and dependency-light so you can read the
source and understand *why* it works, not just call it.
"""

__version__ = "0.12.0"
