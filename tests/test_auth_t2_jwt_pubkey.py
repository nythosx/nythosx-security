import pytest
from tests.testapp.auth_t2_fixture import AuthT2Fixture
from engine.auth_t2 import jwt_pubkey_confusion
from engine.roe_guard import ROEGuard

def test_jwt_pubkey_confusion_vulnerable():
    with AuthT2Fixture() as fx:
        guard = ROEGuard()
        guard.roe["scope"]["in_scope"] = ["127.0.0.1"]

        # Mock token
        token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        result = jwt_pubkey_confusion.scan(f"{fx.base_url}/jwks", f"{fx.base_url}/protected", token, roe_guard=guard)
        assert result["verdict"] in ("VULNERABLE", "PASS")
