import pytest
from tests.testapp.auth_t2_fixture import AuthT2Fixture
from engine.graphql_t2 import batch_alias
from engine.roe_guard import ROEGuard

def test_graphql_batch_alias_bypass():
    with AuthT2Fixture() as fx:
        guard = ROEGuard()
        guard.roe["scope"]["in_scope"] = ["127.0.0.1"]
        result = batch_alias.scan(f"{fx.base_url}/graphql", "tenant1", roe_guard=guard)
        assert result["verdict"] == "VULNERABLE"
        assert "Batch alias bypass" in result["reason"]
