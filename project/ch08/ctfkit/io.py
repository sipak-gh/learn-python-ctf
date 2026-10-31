"""Service I/O: talk to a challenge over a socket, then over pwntools.

CTF services are line- or prompt-oriented TCP servers. You connect, read
until a prompt, send a line, repeat. The standard library can do this, and
doing it by hand once shows what pwntools automates for you.

**Scope / ethics:** only ever point these at a service you are allowed to
touch -- in this course that means your *own* local Docker container on
``127.0.0.1``. Never connect to live competition infrastructure or any host
you do not control.
"""
from __future__ import annotations

import socket
import time

__all__ = ["Service", "pwn_tube"]


class Service:
    """A minimal recv-until / send-line TCP client built on :mod:`socket`.

    This is the "by hand" version. It implements just enough of what you do
    against every networked challenge: connect, buffer incoming bytes, read
    up to a delimiter, and send a line. :func:`pwn_tube` returns the
    practitioner's tool once you understand this.
    """

    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = bytearray()

    def recv(self, n: int = 4096) -> bytes:
        """Read up to ``n`` bytes, draining the internal buffer first."""
        if self._buf:
            chunk = bytes(self._buf[:n])
            del self._buf[:n]
            return chunk
        return self.sock.recv(n)

    def recv_until(self, delim: bytes | str, drop: bool = False) -> bytes:
        """Read until ``delim`` appears; return everything up to and including it.

        With ``drop=True`` the delimiter is stripped from the result. This is
        the core primitive: it is how you wait for a ``"> "`` prompt before
        sending your answer.
        """
        if isinstance(delim, str):
            delim = delim.encode()
        deadline = time.monotonic() + self.timeout
        while delim not in self._buf:
            if time.monotonic() > deadline:
                raise TimeoutError(f"never saw {delim!r}; buffer={bytes(self._buf)!r}")
            data = self.sock.recv(4096)
            if not data:
                raise EOFError(f"connection closed; buffer={bytes(self._buf)!r}")
            self._buf.extend(data)
        idx = self._buf.index(delim) + len(delim)
        out = bytes(self._buf[:idx])
        del self._buf[:idx]
        return out[: -len(delim)] if drop else out

    def recv_line(self, drop: bool = True) -> bytes:
        """Read one ``\\n``-terminated line (newline stripped by default)."""
        return self.recv_until(b"\n", drop=drop)

    def send(self, data: bytes | str) -> None:
        """Send raw bytes."""
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data)

    def send_line(self, data: bytes | str = b"") -> None:
        """Send ``data`` followed by a newline."""
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + b"\n")

    def send_line_after(self, delim: bytes | str, data: bytes | str) -> bytes:
        """Wait for ``delim``, then send ``data`` + newline. Returns what was read."""
        got = self.recv_until(delim)
        self.send_line(data)
        return got

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "Service":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def pwn_tube(host: str, port: int, **kwargs):
    """Return a pwntools ``remote`` tube for the same job as :class:`Service`.

    pwntools is what you reach for under time pressure: it has ``recvuntil``,
    ``sendlineafter``, ``interactive``, logging, and tube-to-tube plumbing.
    Imported lazily so :mod:`ctfkit` stays usable without pwntools installed.

    Only use this against your own local container (``127.0.0.1``).
    """
    from pwn import remote

    return remote(host, port, **kwargs)
