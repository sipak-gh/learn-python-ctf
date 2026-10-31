import socket
import threading

import pytest

from ctfkit import io


def _echo_server():
    """A tiny server that prompts, reads a line, and echoes it back."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def handle():
        conn, _ = srv.accept()
        conn.sendall(b"name> ")
        data = conn.recv(1024)
        conn.sendall(b"hello " + data)
        conn.close()
        srv.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


def test_service_recv_until_and_send_line():
    port = _echo_server()
    with io.Service("127.0.0.1", port, timeout=5) as svc:
        prompt = svc.recv_until(b"> ")
        assert prompt == b"name> "
        svc.send_line(b"world")
        line = svc.recv_line()
        assert line == b"hello world"
