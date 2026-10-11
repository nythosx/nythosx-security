import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import oob_registry
from engine.chain_engine import ChainOrchestrator


class _AllowAllGuard:
    def check_url(self, url, method="GET"):
        return True


def _make_handler(verdict="PASS", reason="", evidence=None, sets_facts=None):
    def handler(orch, args):
        if sets_facts:
            for k, v in sets_facts.items():
                orch.add_fact(k, v, source="test_harness")
        return {
            "verdict": verdict,
            "reason": reason,
            "evidence": evidence or {},
        }
    return handler


def _make_orch(**kwargs):
    return ChainOrchestrator("http://test.local", roe_guard=_AllowAllGuard(),
                             engine_cfg={}, **kwargs)


def _silence_recon(orch):
    orch.run_recon = lambda: None


def test_oob_registry_returns_singleton():
    oob_registry.reset_shared_oob()
    try:
        a = oob_registry.get_shared_oob()
        b = oob_registry.get_shared_oob()
        assert a is b
        assert a.base_url.startswith("http://")
    finally:
        oob_registry.reset_shared_oob()


def test_oob_registry_reset():
    oob_registry.reset_shared_oob()
    a = oob_registry.get_shared_oob()
    oob_registry.reset_shared_oob()
    b = oob_registry.get_shared_oob()
    try:
        assert a is not b
    finally:
        oob_registry.reset_shared_oob()


def test_oob_registry_base_url_helper():
    oob_registry.reset_shared_oob()
    try:
        base = oob_registry.shared_oob_base()
        assert base.startswith("http://127.0.0.1:")
    finally:
        oob_registry.reset_shared_oob()


def test_kill_on_vuln_stops_after_first_finding():
    orch = _make_orch(kill_on_vuln=True)
    orch._TOOL_HANDLERS = {
        "v": _make_handler("VULNERABLE", "boom",
                            evidence={"severity": "high"}),
        "p": _make_handler("PASS", "ok"),
    }
    _silence_recon(orch)
    chains = [
        {"id": "a", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "framework"}]},
         "steps": [{"id": "s1", "tool": "v"}]},
        {"id": "b", "priority": 50,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "framework"}]},
         "steps": [{"id": "s1", "tool": "p"}]},
    ]
    orch.add_fact("framework", "generic")
    report = orch.run(chains=chains)
    assert report["verdict"] == "VULNERABLE"
    executed_ids = [c["id"] for c in report["chain_results"]]
    assert "a" in executed_ids
    assert "b" not in executed_ids
    assert orch.stopped_reason is not None
    assert "kill_on_vuln" in orch.stopped_reason


def test_kill_on_vuln_off_runs_all_chains():
    orch = _make_orch(kill_on_vuln=False)
    orch._TOOL_HANDLERS = {
        "v": _make_handler("VULNERABLE", "boom"),
        "p": _make_handler("PASS", "ok"),
    }
    _silence_recon(orch)
    chains = [
        {"id": "a", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "framework"}]},
         "steps": [{"id": "s1", "tool": "v"}]},
        {"id": "b", "priority": 50,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "framework"}]},
         "steps": [{"id": "s1", "tool": "p"}]},
    ]
    orch.add_fact("framework", "generic")
    report = orch.run(chains=chains)
    executed_ids = [c["id"] for c in report["chain_results"]]
    assert "a" in executed_ids
    assert "b" in executed_ids


def test_stopped_reason_none_when_no_stop():
    orch = _make_orch(kill_on_vuln=True)
    orch._TOOL_HANDLERS = {"p": _make_handler("PASS")}
    _silence_recon(orch)
    chains = [
        {"id": "a", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "framework"}]},
         "steps": [{"id": "s1", "tool": "p"}]},
    ]
    orch.add_fact("framework", "generic")
    orch.run(chains=chains)
    assert orch.stopped_reason is None


def test_extract_versions_parses_server():
    orch = _make_orch()
    v = orch._extract_versions("nginx/1.18.0", "")
    assert v["server_product"] == "nginx"
    assert v["server_version"] == "1.18.0"


def test_extract_versions_parses_powered_by():
    orch = _make_orch()
    v = orch._extract_versions("", "PHP/8.1.2")
    assert v["powered_product"] == "PHP"
    assert v["powered_version"] == "8.1.2"


def test_extract_versions_both():
    orch = _make_orch()
    v = orch._extract_versions("Apache/2.4.41 (Ubuntu)", "PHP/8.1.2")
    assert v["server_product"] == "Apache"
    assert v["server_version"] == "2.4.41"
    assert v["powered_product"] == "PHP"
    assert v["powered_version"] == "8.1.2"


def test_extract_versions_handles_missing():
    orch = _make_orch()
    assert orch._extract_versions("", "") == {}
    assert orch._extract_versions("gunicorn", "") == {}
    assert orch._extract_versions("nginx", "") == {}


def test_extract_versions_no_version_number():
    orch = _make_orch()
    v = orch._extract_versions("nginx", "PHP")
    assert "server_product" not in v
    assert "powered_product" not in v


def test_dynamic_escalation_triggers_new_chain():
    executed = []
    orch = _make_orch()
    orch._TOOL_HANDLERS = {
        "set_gql": _make_handler("PASS", "set",
                                  sets_facts={"has_graphql": True}),
        "pass": _make_handler("PASS", "ok"),
    }
    _silence_recon(orch)

    original_execute = orch.execute_chain

    def _record(chain):
        executed.append(chain["id"])
        return original_execute(chain)

    orch.execute_chain = _record

    chains = [
        {"id": "first", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_start"}]},
         "steps": [{"id": "s1", "tool": "set_gql"}]},
        {"id": "second", "priority": 50,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_graphql"}]},
         "steps": [{"id": "s1", "tool": "pass"}]},
    ]
    orch.add_fact("has_start", True)
    orch.run(chains=chains)

    assert "first" in executed
    assert "second" in executed


def test_dynamic_escalation_avoids_reexecution():
    executed = []
    orch = _make_orch()
    orch._TOOL_HANDLERS = {"pass": _make_handler("PASS")}
    _silence_recon(orch)

    original_execute = orch.execute_chain

    def _record(chain):
        executed.append(chain["id"])
        return original_execute(chain)

    orch.execute_chain = _record

    chains = [
        {"id": "a", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_start"}]},
         "steps": [{"id": "s1", "tool": "pass"}]},
    ]
    orch.add_fact("has_start", True)
    orch.run(chains=chains)
    assert executed.count("a") == 1


def test_dynamic_escalation_plan_is_accumulated():
    orch = _make_orch()
    orch._TOOL_HANDLERS = {
        "set_gql": _make_handler("PASS", "set",
                                  sets_facts={"has_graphql": True}),
        "pass": _make_handler("PASS"),
    }
    _silence_recon(orch)

    chains = [
        {"id": "first", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_start"}]},
         "steps": [{"id": "s1", "tool": "set_gql"}]},
        {"id": "second", "priority": 50,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_graphql"}]},
         "steps": [{"id": "s1", "tool": "pass"}]},
    ]
    orch.add_fact("has_start", True)
    orch.run(chains=chains)
    assert "first" in orch.plan
    assert "second" in orch.plan


def test_confidence_in_finding():
    orch = _make_orch()
    orch._TOOL_HANDLERS = {
        "v": _make_handler("VULNERABLE", "boom",
                            evidence={"severity": "high"}),
    }
    _silence_recon(orch)
    chains = [
        {"id": "a", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_start"}]},
         "steps": [{"id": "s1", "tool": "v"}]},
    ]
    orch.add_fact("has_start", True)
    orch.run(chains=chains)
    assert len(orch.findings) == 1
    f = orch.findings[0]
    assert "confidence" in f
    assert isinstance(f["confidence"], float)
    assert 0.0 <= f["confidence"] <= 1.0


def test_confidence_honors_tool_override():
    def _override_tool(orch, args):
        return {"verdict": "VULNERABLE", "reason": "ok",
                "confidence": 0.42}
    orch = _make_orch()
    orch._TOOL_HANDLERS = {"v": _override_tool}
    _silence_recon(orch)
    chains = [
        {"id": "a", "priority": 100,
         "trigger": {"mode": "any",
                     "conditions": [{"fact": "has_start"}]},
         "steps": [{"id": "s1", "tool": "v"}]},
    ]
    orch.add_fact("has_start", True)
    orch.run(chains=chains)
    assert orch.findings[0]["confidence"] == 0.42


def test_step_confidence_defaults():
    orch = _make_orch()
    assert orch._step_confidence({}, {"verdict": "VULNERABLE"}) == 0.9
    assert orch._step_confidence({}, {"verdict": "SUSPICIOUS"}) == 0.6
    assert orch._step_confidence({}, {"verdict": "PASS"}) == 0.8
    assert orch._step_confidence({}, {"verdict": "UNKNOWN"}) == 0.3
    assert orch._step_confidence({}, {"verdict": "NONSENSE"}) == 0.5


def test_blind_ssrf_registered():
    handlers = ChainOrchestrator._TOOL_HANDLERS
    assert "blind_ssrf" in handlers
    assert callable(handlers["blind_ssrf"])


def test_blind_xss_registered():
    handlers = ChainOrchestrator._TOOL_HANDLERS
    assert "blind_xss" in handlers
    assert callable(handlers["blind_xss"])


def test_blind_xss_requires_param():
    orch = _make_orch(allow_destructive=True)
    result = orch._dispatch_tool("blind_xss", {"url": "http://x"})
    assert result["verdict"] == "UNKNOWN"
    assert "param" in result["reason"].lower()


def test_blind_xss_blocked_by_default():
    orch = _make_orch()
    result = orch._dispatch_tool("blind_xss", {"url": "http://x"})
    assert result["verdict"] == "UNKNOWN"
    assert "destructive" in result["reason"].lower()


def test_blind_ssrf_requires_url():
    orch = _make_orch(allow_destructive=True)
    result = orch._dispatch_tool("blind_ssrf", {})
    assert result["verdict"] in ("UNKNOWN", "PASS", "SUSPICIOUS")


def test_blind_ssrf_blocked_by_default():
    orch = _make_orch()
    result = orch._dispatch_tool("blind_ssrf", {"url": "http://x"})
    assert result["verdict"] == "UNKNOWN"
    assert "destructive" in result["reason"].lower()


def test_stop_condition_budget():
    orch = _make_orch()
    orch.max_budget_sec = 0
    assert orch._stop_condition() is True
    assert "budget" in orch.stopped_reason


def test_stop_condition_kill_on_vuln():
    orch = _make_orch(kill_on_vuln=True)
    orch.findings.append({"verdict": "VULNERABLE"})
    assert orch._stop_condition() is True
    assert "kill_on_vuln" in orch.stopped_reason


def test_stop_condition_no_trigger():
    orch = _make_orch(kill_on_vuln=True)
    assert orch._stop_condition() is False
    assert orch.stopped_reason is None


def test_if_previous_chains_through_suspicious():
    orch = _make_orch()
    step = {"id": "s2",
            "if_previous": {"step": "s1", "verdict": "SUSPICIOUS"}}
    prev = [{"id": "s1", "verdict": "SUSPICIOUS"}]
    assert orch._step_skipped_by_previous(step, prev) is False


def test_if_previous_missing_step_skips():
    orch = _make_orch()
    step = {"id": "s2",
            "if_previous": {"step": "s1", "verdict": "SUSPICIOUS"}}
    assert orch._step_skipped_by_previous(step, []) is True


def test_if_previous_empty_cond_does_not_skip():
    orch = _make_orch()
    step = {"id": "s2", "if_previous": {}}
    assert orch._step_skipped_by_previous(
        step, [{"id": "s1", "verdict": "PASS"}]) is False
