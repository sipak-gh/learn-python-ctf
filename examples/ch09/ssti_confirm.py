#!/usr/bin/env python3
"""Confirm and fingerprint SSTI with ctfkit.web.ssti_probes.

Server-Side Template Injection: user input reaches ``render_template_string``,
so Jinja2 *evaluates* it instead of treating it as text. The tell is that
``{{7*7}}`` comes back as ``49``. :func:`ctfkit.web.ssti_probes` returns the
probe family; we fire them at a LOCAL vulnerable app and read the responses.
"""
import threading
import time

import requests
from flask import Flask, render_template_string, request
from werkzeug.serving import make_server

from ctfkit.web import ssti_probes

app = Flask(__name__)


@app.route("/render")
def render():
    # The bug: attacker input is rendered as a Jinja2 template.
    return render_template_string(request.args.get("q", ""))


srv = make_server("127.0.0.1", 8072, app)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.5)
try:
    for probe in ssti_probes():
        r = requests.get("http://127.0.0.1:8072/render",
                         params={"q": probe}, timeout=5)
        print(f"{probe!r:30} -> {r.text!r}")
finally:
    srv.shutdown()
