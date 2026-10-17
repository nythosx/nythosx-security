import pytest
from engine import runtime_escape

def test_runtime_escape_gated():
    res = runtime_escape.probe("http://127.0.0.1", allow_destructive=False)
    assert res["verdict"] == "UNKNOWN"
