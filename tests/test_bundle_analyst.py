import json

import pytest

from engine.brains.bundle_analyst import BundleAnalyst, clear_cache


@pytest.fixture(autouse=True)
def _isolate_cache():
    clear_cache()
    yield
    clear_cache()


def test_offline_returns_empty():
    ba = BundleAnalyst(client=None)
    result = ba.analyze("const x = 1;")
    assert result["endpoints"] == []
    assert result["secrets"] == []


def test_empty_input_returns_empty():
    ba = BundleAnalyst(client=None)
    result = ba.analyze("")
    assert result["endpoints"] == []


def test_client_parses_valid_json():
    def client(prompt):
        return json.dumps({
            "endpoints": ["/api/users", "/api/orders"],
            "secrets": [{"type": "aws_key", "match": "AKIA..."}],
            "auth_flow": ["login -> token -> me"],
            "debug_flags": ["window.__DEBUG__"],
            "crypto": [{"op": "AES-CBC", "weakness": "no MAC"}],
        })
    ba = BundleAnalyst(client=client)
    result = ba.analyze("const bundle = 1;")
    assert "/api/users" in result["endpoints"]
    assert result["secrets"][0]["type"] == "aws_key"
    assert result["crypto"][0]["op"] == "AES-CBC"


def test_cache_returns_same_object():
    calls = {"n": 0}

    def client(prompt):
        calls["n"] += 1
        return json.dumps({"endpoints": ["/x"]})

    ba = BundleAnalyst(client=client)
    a = ba.analyze("const x = 1;")
    b = ba.analyze("const x = 1;")
    assert a == b
    assert calls["n"] == 1


def test_different_bundles_different_cache_entries():
    calls = {"n": 0}

    def client(prompt):
        calls["n"] += 1
        return json.dumps({"endpoints": ["/x"]})

    ba = BundleAnalyst(client=client)
    ba.analyze("const a = 1;")
    ba.analyze("const b = 2;")
    assert calls["n"] == 2


def test_garbage_falls_back():
    ba = BundleAnalyst(client=lambda p: "not json")
    result = ba.analyze("const x = 1;")
    assert result["endpoints"] == []


def test_truncates_long_input():
    captured = {}

    def client(prompt):
        captured["prompt"] = prompt
        return json.dumps({"endpoints": []})

    ba = BundleAnalyst(client=client)
    ba.analyze("x" * 200_000)
    assert len(captured["prompt"]) < 200_000
