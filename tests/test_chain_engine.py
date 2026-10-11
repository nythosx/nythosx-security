
import pytest

from engine.chain_engine import ChainOrchestrator, run_chain, _default_chains
from engine.roe_guard import ROEViolation


class _AllowAllGuard:
    def check_url(self, url, method="GET"):
        return True


class _BlockAllGuard:
    def check_url(self, url, method="GET"):
        raise ROEViolation("test block")


def _make_orch(target="http://test.local"):
    return ChainOrchestrator(target, roe_guard=_AllowAllGuard(),
                             engine_cfg={})


class _TestChainOrch(ChainOrchestrator):
    _TOOL_HANDLERS = {
        "fake_pass": lambda self, args: {"verdict": "PASS", "reason": "ok"},
        "fake_vuln": lambda self, args: {
            "verdict": "VULNERABLE", "reason": "boom",
            "evidence": {"secret": "abc123"},
        },
        "fake_susp": lambda self, args: {
            "verdict": "SUSPICIOUS", "reason": "maybe",
        },
        "fake_unknown": lambda self, args: {
            "verdict": "UNKNOWN", "reason": "hmm",
        },
        "fake_error": lambda self, args: (
            _ for _ in ()
        ).throw(RuntimeError("boom")),
    }


def _make_test_orch():
    return _TestChainOrch("http://test.local", roe_guard=_AllowAllGuard(),
                          engine_cfg={})


def test_fact_management():
    orch = _make_orch()
    assert not orch.has_fact("framework")
    orch.add_fact("framework", "laravel")
    assert orch.has_fact("framework")
    assert orch.has_fact("framework", "laravel")
    assert not orch.has_fact("framework", "django")
    assert orch.get_fact("framework") == "laravel"
    assert orch.get_fact("missing") is None
    assert orch.get_fact("missing", "default") == "default"


def test_context_management():
    orch = _make_orch()
    assert orch.get_context("api_base") is None
    orch.set_context("api_base", "http://x")
    assert orch.get_context("api_base") == "http://x"


def test_resolve_args_substitutes_context():
    orch = _make_orch()
    orch.set_context("api_base", "http://test")
    orch.add_fact("framework", "laravel")
    resolved = orch._resolve_args({
        "target": "{{ api_base }}",
        "fw": "{{ framework }}",
        "literal": "static",
        "num": 42,
    })
    assert resolved["target"] == "http://test"
    assert resolved["fw"] == "laravel"
    assert resolved["literal"] == "static"
    assert resolved["num"] == 42


def test_resolve_args_nested():
    orch = _make_orch()
    orch.set_context("t", "x")
    resolved = orch._resolve_args({
        "list": ["{{ t }}", "literal"],
        "nested": {"k": "{{ t }}"},
    })
    assert resolved["list"] == ["x", "literal"]
    assert resolved["nested"] == {"k": "x"}


def test_resolve_args_missing_key():
    orch = _make_orch()
    resolved = orch._resolve_args({"x": "{{ missing }}"})
    assert resolved["x"] == ""


def test_matches_trigger_any():
    orch = _make_orch()
    orch.add_fact("has_jwt", True)
    assert orch._matches_trigger({
        "mode": "any",
        "conditions": [{"fact": "has_jwt"}, {"fact": "has_login"}],
    }) is True


def test_matches_trigger_all():
    orch = _make_orch()
    orch.add_fact("has_jwt", True)
    assert orch._matches_trigger({
        "mode": "all",
        "conditions": [{"fact": "has_jwt"}, {"fact": "has_login"}],
    }) is False


def test_matches_trigger_none():
    orch = _make_orch()
    assert orch._matches_trigger({
        "mode": "none",
        "conditions": [{"fact": "has_jwt"}],
    }) is True


def test_matches_trigger_with_value():
    orch = _make_orch()
    orch.add_fact("framework", "laravel")
    assert orch._matches_trigger({
        "mode": "any",
        "conditions": [{"fact": "framework", "value": "laravel"}],
    }) is True
    assert orch._matches_trigger({
        "mode": "any",
        "conditions": [{"fact": "framework", "value": "django"}],
    }) is False


def test_matches_trigger_empty():
    orch = _make_orch()
    assert orch._matches_trigger({}) is False


def test_chain_pass_continues():
    orch = _make_test_orch()
    chain = {
        "id": "test", "name": "Test",
        "steps": [
            {"id": "s1", "tool": "fake_pass"},
            {"id": "s2", "tool": "fake_pass"},
        ],
    }
    result = orch.execute_chain(chain)
    assert len(result["steps"]) == 2
    assert result["verdict"] == "UNKNOWN"
    assert all(s["verdict"] == "PASS" for s in result["steps"])


def test_chain_vulnerable_stops():
    orch = _make_test_orch()
    chain = {
        "id": "test", "name": "Test",
        "steps": [
            {"id": "s1", "tool": "fake_pass"},
            {"id": "s2", "tool": "fake_vuln"},
            {"id": "s3", "tool": "fake_pass"},
        ],
    }
    result = orch.execute_chain(chain)
    assert result["verdict"] == "VULNERABLE"
    assert len(result["steps"]) == 2
    assert len(orch.findings) == 1
    assert orch.findings[0]["chain"] == "test"


def test_chain_suspicious_records_but_continues():
    orch = _make_test_orch()
    chain = {
        "id": "test", "name": "Test",
        "steps": [
            {"id": "s1", "tool": "fake_susp"},
            {"id": "s2", "tool": "fake_pass"},
        ],
    }
    result = orch.execute_chain(chain)
    assert len(result["steps"]) == 2
    assert result["verdict"] == "SUSPICIOUS"
    assert len(orch.findings) == 0


def test_chain_vuln_after_susp_wins():
    orch = _make_test_orch()
    chain = {
        "id": "test", "name": "Test",
        "steps": [
            {"id": "s1", "tool": "fake_susp"},
            {"id": "s2", "tool": "fake_vuln"},
        ],
    }
    result = orch.execute_chain(chain)
    assert result["verdict"] == "VULNERABLE"


def test_on_fail_abort_stops_on_pass():
    orch = _make_test_orch()
    chain = {
        "id": "test", "name": "Test",
        "steps": [
            {"id": "s1", "tool": "fake_pass", "on_fail": "abort"},
            {"id": "s2", "tool": "fake_pass"},
        ],
    }
    result = orch.execute_chain(chain)
    assert len(result["steps"]) == 1


def test_step_precondition_skips_when_fact_missing():
    orch = _make_test_orch()
    chain = {
        "id": "test", "name": "Test",
        "steps": [
            {"id": "s1", "tool": "fake_pass",
             "precondition": {"mode": "all",
                              "conditions": [{"fact": "missing"}]}},
        ],
    }
    result = orch.execute_chain(chain)
    assert len(result["steps"]) == 1
    assert result["steps"][0]["verdict"] == "SKIP"


def test_step_precondition_runs_when_fact_present():
    orch = _make_test_orch()
    orch.add_fact("has_jwt", True)
    chain = {
        "id": "test", "name": "Test",
        "steps": [
            {"id": "s1", "tool": "fake_pass",
             "precondition": {"mode": "all",
                              "conditions": [{"fact": "has_jwt"}]}},
        ],
    }
    result = orch.execute_chain(chain)
    assert result["steps"][0]["verdict"] == "PASS"


def test_tool_exception_returns_unknown():
    orch = _make_test_orch()
    chain = {
        "id": "test", "name": "Test",
        "steps": [{"id": "s1", "tool": "fake_error"}],
    }
    result = orch.execute_chain(chain)
    assert result["steps"][0]["verdict"] == "UNKNOWN"
    assert "boom" in result["steps"][0]["reason"]


def test_unknown_tool_returns_unknown():
    orch = _make_test_orch()
    chain = {
        "id": "test", "name": "Test",
        "steps": [{"id": "s1", "tool": "does_not_exist"}],
    }
    result = orch.execute_chain(chain)
    assert result["steps"][0]["verdict"] == "UNKNOWN"
    assert "unknown tool" in result["steps"][0]["reason"]


def test_apply_step_context_exports_from_evidence():
    orch = _make_test_orch()
    step = {"id": "s1", "tool": "fake_vuln",
            "exports": {"secret": "evidence.secret"}}
    result = {"verdict": "VULNERABLE", "evidence": {"secret": "abc123"}}
    orch._apply_step_context(step, result)
    assert orch.get_context("secret") == "abc123"
    assert orch.has_fact("secret")


def test_apply_step_context_skips_missing_path():
    orch = _make_test_orch()
    step = {"id": "s1", "tool": "fake_vuln",
            "exports": {"secret": "evidence.missing"}}
    orch._apply_step_context(step, {"evidence": {"other": "x"}})
    assert orch.get_context("secret") is None


def test_select_chains_filters_by_trigger():
    orch = _make_orch()
    orch.add_fact("has_jwt", True)
    chains = [
        {"id": "a", "priority": 10,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_jwt"}]},
         "steps": []},
        {"id": "b", "priority": 20,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_graphql"}]},
         "steps": []},
    ]
    selected = orch.select_chains(chains)
    assert [c["id"] for c in selected] == ["a"]


def test_select_chains_sorts_by_priority():
    orch = _make_orch()
    orch.add_fact("has_jwt", True)
    chains = [
        {"id": "low", "priority": 10,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_jwt"}]},
         "steps": []},
        {"id": "high", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_jwt"}]},
         "steps": []},
    ]
    selected = orch.select_chains(chains)
    assert [c["id"] for c in selected] == ["high", "low"]


def test_roe_gate_blocks_out_of_scope():
    with pytest.raises(RuntimeError, match="ROE_BLOCK"):
        ChainOrchestrator("http://any", roe_guard=_BlockAllGuard(),
                          engine_cfg={})


def test_roe_gate_allows_in_scope():
    orch = ChainOrchestrator("http://any", roe_guard=_AllowAllGuard(),
                             engine_cfg={})
    assert orch.target == "http://any"


def test_final_report_shape():
    orch = _make_test_orch()
    chain = {
        "id": "test", "name": "Test",
        "steps": [{"id": "s1", "tool": "fake_vuln"}],
    }
    orch.execute_chain(chain)
    report = orch._final_report()
    assert report["verdict"] == "VULNERABLE"
    assert "facts" in report
    assert "context" in report
    assert "chain_results" in report
    assert "findings" in report
    assert report["target"] == "http://test.local"


def test_run_chain_with_no_chains_returns_report(monkeypatch):
    def _noop_recon(self):
        return None
    monkeypatch.setattr(ChainOrchestrator, "run_recon", _noop_recon)
    report = run_chain("http://test.local", roe_guard=_AllowAllGuard(),
                       engine_cfg={}, chains=[])
    assert isinstance(report, dict)
    assert report["verdict"] == "UNKNOWN"
    assert report["chain_results"] == []


def test_default_chains_reflects_registry_state():
    chains = _default_chains()
    assert isinstance(chains, list)
    try:
        from engine.chain_registry import get_all_chains
    except ImportError:
        assert chains == []
    else:
        assert chains == get_all_chains()
        assert len(chains) >= 9


def test_fact_store_mirrors_add_fact():
    orch = _make_orch()
    orch.add_fact("framework", "laravel", source="recon", confidence="high")
    assert orch.fact_store.has("framework", min_confidence=0.9)
    assert orch.fact_store.get("framework") == "laravel"


def test_fact_store_confidence_from_string():
    orch = _make_orch()
    orch.add_fact("hint", True, source="recon", confidence="low")
    assert orch.fact_store.confidence("hint") == 0.3
    orch.add_fact("hint2", True, source="recon", confidence="high")
    assert orch.fact_store.confidence("hint2") == 1.0


def test_select_chains_uses_adaptive_scoring():
    orch = _make_orch()
    orch.add_fact("has_jwt", True, source="recon", confidence="high")
    chains = [
        {"id": "jwt", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_jwt"}]},
         "steps": []},
        {"id": "other", "priority": 90,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_graphql"}]},
         "steps": []},
    ]
    selected = orch.select_chains(chains)
    ids = [c["id"] for c in selected]
    assert "jwt" in ids
    assert "other" not in ids


def test_select_chains_confidence_affects_order():
    orch = _make_orch()
    orch.add_fact("has_jwt", True, source="recon", confidence="low")
    orch.add_fact("has_graphql", True, source="recon", confidence="high")
    chains = [
        {"id": "jwt", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_jwt"}]},
         "steps": []},
        {"id": "graphql", "priority": 50,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_graphql"}]},
         "steps": []},
    ]
    selected = orch.select_chains(chains)
    ids = [c["id"] for c in selected]
    assert "graphql" in ids and "jwt" in ids
    assert ids.index("graphql") < ids.index("jwt")


def test_step_skipped_by_previous_no_cond():
    orch = _make_orch()
    assert not orch._step_skipped_by_previous(
        {"id": "s2"}, [{"id": "s1", "verdict": "PASS"}])


def test_step_skipped_by_previous_cond_matches():
    orch = _make_orch()
    step = {"id": "s2",
            "if_previous": {"step": "s1", "verdict": "SUSPICIOUS"}}
    prev = [{"id": "s1", "verdict": "SUSPICIOUS"}]
    assert not orch._step_skipped_by_previous(step, prev)


def test_step_skipped_by_previous_cond_differs():
    orch = _make_orch()
    step = {"id": "s2",
            "if_previous": {"step": "s1", "verdict": "SUSPICIOUS"}}
    prev = [{"id": "s1", "verdict": "PASS"}]
    assert orch._step_skipped_by_previous(step, prev)


def test_step_skipped_by_previous_missing_target():
    orch = _make_orch()
    step = {"id": "s2",
            "if_previous": {"step": "nonexistent", "verdict": "SUSPICIOUS"}}
    assert orch._step_skipped_by_previous(step, [{"id": "s1", "verdict": "PASS"}])


def test_if_previous_skips_step_in_chain():
    orch = _make_test_orch()
    chain = {
        "id": "t", "name": "t",
        "steps": [
            {"id": "s1", "tool": "fake_pass"},
            {"id": "s2", "tool": "fake_vuln",
             "if_previous": {"step": "s1", "verdict": "SUSPICIOUS"}},
        ],
    }
    result = orch.execute_chain(chain)
    assert len(result["steps"]) == 2
    assert result["steps"][0]["verdict"] == "PASS"
    assert result["steps"][1]["verdict"] == "SKIP"


def test_register_tool_extends_handlers():
    from engine.chain_engine import register_tool, ChainOrchestrator

    def custom(orch, args):
        return {"verdict": "PASS", "reason": "custom"}

    register_tool("test_custom_tool", custom)
    assert "test_custom_tool" in ChainOrchestrator._TOOL_HANDLERS
    orch = _make_orch()
    result = orch._dispatch_tool("test_custom_tool", {})
    assert result["verdict"] == "PASS"
