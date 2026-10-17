import pytest
from tests.testapp.auth_t2_fixture import AuthT2Fixture
from engine.auth_t2 import cookie_matrix
from engine.roe_guard import ROEGuard

def test_cookie_last_wins():
    with AuthT2Fixture() as fx:
        guard = ROEGuard()
        guard.roe["scope"]["in_scope"] = ["127.0.0.1"]
        result = cookie_matrix.scan(f"{fx.base_url}/protected", "session_id", roe_guard=guard)
        assert result["verdict"] == "VULNERABLE"
        assert "Last-wins" in result["reason"]
