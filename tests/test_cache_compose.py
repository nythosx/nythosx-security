import pytest
from engine.desync import cache_compose

def test_cache_compose_deferred():
    res = cache_compose.compose("http://127.0.0.1")
    assert res["verdict"] == "SUSPICIOUS"
