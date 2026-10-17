import pytest
from tests.testapp.tenant_fixture import TenantFixture
from engine.tenant import multi_tenant
from engine.roe_guard import ROEGuard

def test_tenant_bola():
    with TenantFixture() as fx:
        guard = ROEGuard()
        guard.roe["scope"]["in_scope"] = ["127.0.0.1"]
        res = multi_tenant.sweep(fx.base_url, "token_a", "token_b", roe_guard=guard)
        assert res["verdict"] == "VULNERABLE"
