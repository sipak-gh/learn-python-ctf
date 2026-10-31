#!/usr/bin/env python3
"""requests basics against a tiny LOCAL Flask app (sessions, params, cookies).

The practitioner tool for web challenges is :mod:`requests`. A ``Session``
keeps cookies across calls; ``params=`` builds the query string; ``cookies=``
and ``headers=`` set what you send. We run a throwaway Flask app on 127.0.0.1
in a background thread -- never a remote host -- and talk to it.
"""
import threading
import time

import requests
from flask import Flask, request
from werkzeug.serving import make_server

app = Flask(__name__)


@app.route("/echo")
def echo():
    return f"you sent name={request.args.get('name')}"


@app.route("/setcookie")
def setcookie():
    resp = app.make_response("cookie set")
    resp.set_cookie("token", "s3cr3t")
    return resp


@app.route("/whoami")
def whoami():
    return f"token={request.cookies.get('token')}"


srv = make_server("127.0.0.1", 8071, app)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.5)
try:
    s = requests.Session()
    print(s.get("http://127.0.0.1:8071/echo", params={"name": "ctf"}).text)
    s.get("http://127.0.0.1:8071/setcookie")          # server sets a cookie
    print("session cookies:", s.cookies.get_dict())
    print(s.get("http://127.0.0.1:8071/whoami").text)  # cookie sent back
finally:
    srv.shutdown()
