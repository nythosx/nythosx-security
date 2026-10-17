import pytest
from engine import campaign
from engine.roe_guard import ROEGuard

def test_campaign_run():
    guard = ROEGuard()
    guard.roe["scope"]["in_scope"] = ["127.0.0.1"]
    res = campaign.run("http://127.0.0.1", roe_guard=guard)
    assert res["verdict"] == "VULNERABLE"
    assert "Campaign completed" in res["reason"]
