import pytest
from engine.desync import csd

def test_csd_deferred():
    res = csd.browser_proof("http://127.0.0.1")
    assert res["verdict"] == "PASS"
