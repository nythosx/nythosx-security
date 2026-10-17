import pytest

from engine.identity_broker import (
    IdentityBroker, IdentityContext, _bearer_from_headers,
)


def _make_broker():
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine
    guard = ROEGuard(engine_cfg=load_engine())
    return IdentityBroker("http://127.0.0.1:1", guard)


def test_broker_constructs_with_anon():
    b = _make_broker()
    assert "anon" in b.identities
    assert b.get_all_authenticated() == {}
    assert b.has_two_identities() is False


def test_two_identities_isolated():
    b = _make_broker()
    b.add_identity("user_a", {"Authorization": "Bearer AAA"},
                   {"sid": "a-cookie"}, username="a@x")
    b.add_identity("user_b", {"Authorization": "Bearer BBB"},
                   {"sid": "b-cookie"}, username="b@x")
    a = b.get_identity("user_a")
    c = b.get_identity("user_b")
    assert a.headers["Authorization"] == "Bearer AAA"
    assert c.headers["Authorization"] == "Bearer BBB"
    assert a.cookies["sid"] == "a-cookie"
    assert c.cookies["sid"] == "b-cookie"
    assert b.has_two_identities() is True


def test_identity_token_extraction():
    b = _make_broker()
    b.add_identity("user_a", {"Authorization": "Bearer T-A"})
    assert b.identity_token("user_a") == "T-A"
    assert b.identity_token("missing") == ""


def test_bearer_helper():
    assert _bearer_from_headers({"Authorization": "Bearer xyz"}) == "xyz"
    assert _bearer_from_headers({"authorization": "xyz"}) == "xyz"
    assert _bearer_from_headers({}) == ""
    assert _bearer_from_headers(None) == ""


def test_safe_dict_excludes_credentials():
    ctx = IdentityContext(name="user_a", token="secret-xyz",
                          username="a@x", password="hunter2",
                          headers={"Authorization": "Bearer secret-xyz"})
    safe = ctx.to_safe_dict()
    assert "hunter2" not in str(safe)
    assert "secret-xyz" not in str(safe)
    assert safe["has_token"] is True


def test_publish_facts_writes_availability():
    from engine.facts import FactStore
    fs = FactStore()
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine
    guard = ROEGuard(engine_cfg=load_engine())
    b = IdentityBroker("http://127.0.0.1:1", guard, fact_store=fs)
    assert fs.get("identity_broker_available") is None
    b._publish_facts()
    assert fs.get("identity_broker_available") is False
    b.add_identity("user_a", {"Authorization": "Bearer a"})
    b.add_identity("user_b", {"Authorization": "Bearer b"})
    b._publish_facts()
    assert fs.get("identity_broker_available") is True
    assert fs.has("has_identity_a")
    assert fs.has("has_identity_b")


def test_probe_liveness_unreachable_returns_false():
    b = _make_broker()
    b.add_identity("user_a", {"Authorization": "Bearer a"})
    assert b.probe_liveness("user_a") is False
