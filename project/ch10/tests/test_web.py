import pickle

import pytest

from ctfkit import web


def test_ssti_probes_include_canonical():
    probes = web.ssti_probes()
    assert "{{7*7}}" in probes


def test_pickle_rce_executes_on_load(tmp_path):
    marker = tmp_path / "pwned"
    payload = web.pickle_rce(f"touch {marker}")
    assert not marker.exists()
    pickle.loads(payload)
    assert marker.exists()


def test_pickle_opcode_rce_structure_and_execution():
    # module.func(arg) -> os.system('true') should load and run cleanly.
    payload = web.pickle_opcode_rce("os", "system", "true")
    assert payload.startswith(b"cos\nsystem\n")
    assert payload.endswith(b"R.")
    assert pickle.loads(payload) == 0  # os.system('true') returns 0


def test_object_chain_payload_mentions_subclasses():
    expr = web.object_chain_payload("subprocess")
    assert "__subclasses__" in expr and "subprocess" in expr
