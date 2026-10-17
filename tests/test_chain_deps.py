import pytest

from engine import chain_engine
from engine.chain_engine import ChainOrchestrator, register_tool


def _make_orch(target="http://127.0.0.1:1"):
    from engine import budget as _b
    try:
        _b.auto_configure_from_configs()
    except Exception:
        pass
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine
    guard = ROEGuard(engine_cfg=load_engine())
    return ChainOrchestrator(target, roe_guard=guard,
                             max_budget_sec=5, verbose=False)


def test_tool_spec_registered():
    def fake(orch, args):
        return {"verdict": "PASS", "reason": "ok"}

    register_tool("test_spec_tool", fake,
                  requires=["req_x"], provides=["has_provided_x"])
    spec = chain_engine._TOOL_SPECS.get("test_spec_tool")
    assert spec is not None
    assert spec["requires"] == ["req_x"]
    assert spec["provides"] == ["has_provided_x"]


def test_missing_precondition_blocks_dispatch():
    def fake(orch, args):
        return {"verdict": "VULNERABLE", "reason": "should not run"}

    register_tool("test_blocks_without_req", fake,
                  requires=["never_provided_key"])
    orch = _make_orch()
    result = orch._dispatch_tool("test_blocks_without_req", {})
    assert result["verdict"] == "UNKNOWN"
    assert "preconditions unmet" in result["reason"]
    assert "never_provided_key" in result["evidence"]["missing"]


def test_provider_satisfies_precondition():
    def fake(orch, args):
        return {"verdict": "PASS", "reason": "ran"}

    register_tool("test_needs_provider", fake,
                  requires=["provider_key"])

    orch = _make_orch()
    calls = {"n": 0}

    def provide(store, ctx):
        calls["n"] += 1
        store.add("provider_key", True, source="cli")

    orch.fact_store.register_provider("provider_key", provide)
    result = orch._dispatch_tool("test_needs_provider", {})
    assert result["verdict"] == "PASS"
    assert calls["n"] == 1


def test_effects_become_facts():
    def fake(orch, args):
        return {"verdict": "VULNERABLE", "reason": "found something"}

    register_tool("test_provides_fact", fake,
                  provides=["has_effect_flag"])
    orch = _make_orch()
    orch._dispatch_tool("test_provides_fact", {})
    assert orch.fact_store.has("has_effect_flag")
    assert orch.fact_store.get("has_effect_flag") is True


def test_duplicate_dispatch_skipped():
    def fake(orch, args):
        return {"verdict": "PASS", "reason": "ran"}

    register_tool("test_dup", fake)
    orch = _make_orch()
    step = {"id": "s1", "tool": "test_dup", "args": {"a": 1}}
    first = orch._execute_step("chain-x", step)
    second = orch._execute_step("chain-x", step)
    assert first.get("verdict") == "PASS"
    assert second.get("verdict") == "SKIP"


def test_duplicate_allowed_for_retry():
    def fake(orch, args):
        return {"verdict": "PASS", "reason": "ran"}

    register_tool("test_dup_retry", fake)
    orch = _make_orch()
    step = {"id": "s2", "tool": "test_dup_retry", "args": {"b": 2}}
    orch._execute_step("chain-y", step)
    again = orch._execute_step("chain-y", step, allow_duplicate=True)
    assert again.get("verdict") == "PASS"
