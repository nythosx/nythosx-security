import pytest
from tests.testapp.tenant_fixture import TenantFixture
from engine.tenant import registration
from engine.roe_guard import ROEGuard

def test_mass_assignment_signup():
    with TenantFixture() as fx:
        guard = ROEGuard()
        guard.roe["scope"]["in_scope"] = ["127.0.0.1"]
        res = registration.probe_signup(fx.base_url, roe_guard=guard)
        assert res["verdict"] == "VULNERABLE"
