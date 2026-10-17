import pytest


def test_cross_user_confirmed_when_both_200_distinct(monkeypatch):
    from engine import bola_scanner

    responses = {
        ("http://t.local", "/api/records/42", "token-a"): {
            "url": "http://t.local/api/records/42", "status": 200,
            "ct": "application/json",
            "body": '{"id":42,"owner":"a","amount":100}',
            "parsed": {"id": 42, "owner": "a", "amount": 100},
        },
        ("http://t.local", "/api/records/42", "token-b"): {
            "url": "http://t.local/api/records/42", "status": 200,
            "ct": "application/json",
            "body": '{"id":42,"owner":"b","amount":999}',
            "parsed": {"id": 42, "owner": "b", "amount": 999},
        },
    }

    def fake_get(base, path, token, timeout, verify):
        key = (base.rstrip("/"), path, token)
        if key in responses:
            return responses[key]
        return {"url": base + path, "status": 404, "body": "", "ct": ""}

    monkeypatch.setattr(bola_scanner, "_get", fake_get)

    out = bola_scanner._cross_user_check(
        "http://t.local", "token-a", "token-b",
        ["/api/records/42"],
        timeout=5, verify=False,
    )
    assert out["verdict"] == "VULNERABLE"
    assert "proof" in out["evidence"]
    assert out["evidence"]["status"] == "CONFIRMED"
    assert "response_hashes" in out["evidence"]["proof"]


def test_cross_user_refuted_when_identical_bodies(monkeypatch):
    from engine import bola_scanner

    body = '{"public":true}'
    parsed = {"public": True}

    def fake_get(base, path, token, timeout, verify):
        return {"url": base + path, "status": 200,
                "ct": "application/json", "body": body, "parsed": parsed}

    monkeypatch.setattr(bola_scanner, "_get", fake_get)

    out = bola_scanner._cross_user_check(
        "http://t.local", "token-a", "token-b",
        ["/api/records/1"], timeout=5, verify=False,
    )
    assert out["verdict"] == "PASS"
    assert out["evidence"]["status"] == "REFUTED"


def test_cross_user_inconclusive_when_no_signals(monkeypatch):
    from engine import bola_scanner

    def fake_get(base, path, token, timeout, verify):
        return {"url": base + path, "status": 500,
                "ct": "text/html", "body": "err", "parsed": None}

    monkeypatch.setattr(bola_scanner, "_get", fake_get)

    out = bola_scanner._cross_user_check(
        "http://t.local", "token-a", "token-b",
        ["/api/records/1"], timeout=5, verify=False,
    )
    assert out["verdict"] == "UNKNOWN"
    assert out["evidence"]["status"] == "INCONCLUSIVE"


def test_chain_provider_satisfies_identity_require():
    from engine.chain_engine import ChainOrchestrator, register_tool
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine

    guard = ROEGuard(engine_cfg=load_engine())
    orch = ChainOrchestrator("http://127.0.0.1:1", roe_guard=guard,
                             max_budget_sec=5, verbose=False)

    class FakeBroker:
        def __init__(self):
            from engine.identity_broker import IdentityContext
            self.identities = {
                "anon": IdentityContext(name="anon"),
                "user_a": IdentityContext(name="user_a", token="tok-a"),
                "user_b": IdentityContext(name="user_b", token="tok-b"),
            }

        def initialize(self, adapter=None, paths=None):
            pass

        def has_two_identities(self):
            return True

        def get_identity(self, name):
            return self.identities.get(name)

    orch.identity_broker = FakeBroker()

    def fake_tool(orch, args):
        return {"verdict": "PASS", "reason": "ran"}

    register_tool("test_requires_identity_e2e", fake_tool,
                  requires=["has_identity_a"])

    result = orch._dispatch_tool("test_requires_identity_e2e", {})
    assert result["verdict"] == "PASS"
    assert orch.fact_store.has("has_identity_a")


def test_chain_provider_unmet_returns_unknown():
    from engine.chain_engine import ChainOrchestrator, register_tool
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine

    guard = ROEGuard(engine_cfg=load_engine())
    orch = ChainOrchestrator("http://127.0.0.1:1", roe_guard=guard,
                             max_budget_sec=5, verbose=False)

    class DeadBroker:
        identities = {"anon": None}

        def initialize(self, adapter=None, paths=None):
            pass

        def has_two_identities(self):
            return False

        def get_identity(self, name):
            return None

    orch.identity_broker = DeadBroker()

    def fake_tool(orch, args):
        return {"verdict": "VULNERABLE", "reason": "should not run"}

    register_tool("test_requires_identity_dead_e2e", fake_tool,
                  requires=["has_identity_a"])

    result = orch._dispatch_tool("test_requires_identity_dead_e2e", {})
    assert result["verdict"] == "UNKNOWN"
    assert "preconditions unmet" in result["reason"]


def test_chain_triggers_read_fact_store(monkeypatch):
    from engine.chain_engine import ChainOrchestrator
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine

    guard = ROEGuard(engine_cfg=load_engine())
    orch = ChainOrchestrator("http://127.0.0.1:1", roe_guard=guard,
                             max_budget_sec=5, verbose=False)

    # Write directly to fact_store, bypassing add_fact. Before the fix,
    # has_fact and get_fact could not see this fact.
    orch.fact_store.add("some_broker_only_fact", "yes",
                        source="identity_broker")
    assert orch.has_fact("some_broker_only_fact")
    assert orch.get_fact("some_broker_only_fact") == "yes"


def test_has_id_endpoints_from_js_paths():
    from engine.chain_engine import ChainOrchestrator
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine

    guard = ROEGuard(engine_cfg=load_engine())
    orch = ChainOrchestrator("http://127.0.0.1:1", roe_guard=guard,
                             max_budget_sec=5, verbose=False)
    orch._infer_facts_from_paths(["/api/users/1", "/api/items/2"])
    assert orch.has_fact("has_id_endpoints")


def test_has_id_endpoints_from_templated_paths():
    from engine.chain_engine import ChainOrchestrator
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine

    guard = ROEGuard(engine_cfg=load_engine())
    orch = ChainOrchestrator("http://127.0.0.1:1", roe_guard=guard,
                             max_budget_sec=5, verbose=False)
    orch._infer_facts_from_paths(["/api/items/{id}"])
    assert orch.has_fact("has_id_endpoints")
