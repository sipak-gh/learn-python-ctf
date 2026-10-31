#!/usr/bin/env python3
"""Talk to a TCP service with the standard library, then with ctfkit.Service.

A challenge service is a prompt-and-reply loop: it prints a prompt, you send a
line, it replies. To keep this self-contained and *local* (ethics: only ever
touch services you control), we start a tiny echo server on 127.0.0.1 in a
background thread, then connect to it two ways.
"""
import socket
import threading

from ctfkit.io import Service


def start_server() -> int:
    """A throwaway local server: prompt, read a line, reply. Returns its port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))        # port 0 = let the OS pick a free one
    srv.listen(1)
    port = srv.getsockname()[1]

    def handle():
        conn, _ = srv.accept()
        conn.sendall(b"name> ")
        name = conn.recv(1024).strip()
        conn.sendall(b"hello " + name + b"\n")
        conn.close()
        srv.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


def by_hand(port: int) -> None:
    """The raw-socket version: buffer bytes, find the prompt, send a line."""
    sock = socket.create_connection(("127.0.0.1", port))
    buf = b""
    while b"> " not in buf:              # recv until we see the prompt
        buf += sock.recv(4096)
    print("raw prompt:", buf.decode().strip())
    sock.sendall(b"world\n")             # you must add the newline yourself
    print("raw reply :", sock.recv(4096).decode().strip())
    sock.close()


def with_ctfkit(port: int) -> None:
    """The same conversation through ctfkit.Service -- intent is obvious."""
    with Service("127.0.0.1", port) as svc:
        prompt = svc.recv_until(b"> ")
        print("svc prompt:", prompt.decode().strip())
        svc.send_line(b"world")
        print("svc reply :", svc.recv_line().decode())


if __name__ == "__main__":
    by_hand(start_server())
    with_ctfkit(start_server())
