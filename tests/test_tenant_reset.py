import pytest
from tests.testapp.tenant_fixture import TenantFixture
from engine.tenant import password_reset_matrix
from engine.roe_guard import ROEGuard

def test_reset_entropy():
    with TenantFixture() as fx:
        guard = ROEGuard()
        guard.roe["scope"]["in_scope"] = ["127.0.0.1"]
        res = password_reset_matrix.probe_entropy(fx.base_url, "test@test.com", roe_guard=guard)
        assert res["verdict"] == "SUSPICIOUS"
