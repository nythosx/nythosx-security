import pytest

from engine.chain_engine import ChainOrchestrator


class _Allow:
    def check_url(self, url, method="GET"):
        return True


def _make_orch(handlers, allow_destructive=True):
    orch = ChainOrchestrator("http://test.local", roe_guard=_Allow(),
                             engine_cfg={}, allow_destructive=allow_destructive)
    orch.run_recon = lambda: None
    orch._TOOL_HANDLERS = handlers
    return orch


def test_confirms_when_retry_also_vulnerable():
    calls = {"n": 0}

    def always_vuln(orch, args):
        calls["n"] += 1
        return {"verdict": "VULNERABLE", "reason": "boom", "evidence": {}}

    orch = _make_orch({"t": always_vuln})
    orch._is_idempotent_tool = lambda name: True
    chain = {"id": "c", "name": "c",
             "trigger": {"mode": "any", "conditions": [{"fact": "framework"}]},
             "steps": [{"id": "s1", "tool": "t"}]}
    orch.add_fact("framework", "generic")
    result = orch.execute_chain(chain)
    step = result["steps"][0]
    assert step["verdict"] == "VULNERABLE"
    assert step["confirmation_status"] == "confirmed"
    assert calls["n"] == 2


def test_downgrades_when_retry_returns_pass():
    calls = {"n": 0}

    def flaky(orch, args):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"verdict": "VULNERABLE", "reason": "first try", "evidence": {}}
        return {"verdict": "PASS", "reason": "second try passed", "evidence": {}}

    orch = _make_orch({"t": flaky})
    orch._is_idempotent_tool = lambda name: True
    chain = {"id": "c", "name": "c",
             "trigger": {"mode": "any", "conditions": [{"fact": "framework"}]},
             "steps": [{"id": "s1", "tool": "t"}]}
    orch.add_fact("framework", "generic")
    result = orch.execute_chain(chain)
    step = result["steps"][0]
    assert step["verdict"] == "SUSPICIOUS"
    assert step["confirmation_status"] == "unconfirmed"
    assert "[unconfirmed" in step["reason"]
    assert calls["n"] == 2


def test_non_vulnerable_not_confirmed():
    calls = {"n": 0}

    def always_pass(orch, args):
        calls["n"] += 1
        return {"verdict": "PASS", "reason": "clean", "evidence": {}}

    orch = _make_orch({"t": always_pass})
    chain = {"id": "c", "name": "c",
             "trigger": {"mode": "any", "conditions": [{"fact": "framework"}]},
             "steps": [{"id": "s1", "tool": "t"}]}
    orch.add_fact("framework", "generic")
    result = orch.execute_chain(chain)
    step = result["steps"][0]
    assert step["verdict"] == "PASS"
    assert "confirmation_status" not in step
    assert calls["n"] == 1


def test_destructive_tools_not_confirmed():
    calls = {"n": 0}

    def destructive(orch, args):
        calls["n"] += 1
        return {"verdict": "VULNERABLE", "reason": "boom", "evidence": {}}

    orch = _make_orch({"timing_robust": destructive})
    chain = {"id": "c", "name": "c",
             "trigger": {"mode": "any", "conditions": [{"fact": "framework"}]},
             "steps": [{"id": "s1", "tool": "timing_robust"}]}
    orch.add_fact("framework", "generic")
    orch.execute_chain(chain)
    assert calls["n"] == 1


def test_is_idempotent_tool_unknown_is_false():
    orch = _make_orch({})
    assert orch._is_idempotent_tool("nonexistent-tool") is False


def test_is_idempotent_tool_destructive_false():
    orch = _make_orch({})
    assert orch._is_idempotent_tool("weak_credential_enum") is False


def test_is_idempotent_tool_maps_chain_name_to_capability():
    orch = _make_orch({})
    assert orch._is_idempotent_tool("lockout_scan") is False
    assert orch._is_idempotent_tool("cloud_storage") is True


def test_confirm_skipped_when_budget_exceeded():
    calls = {"n": 0}

    def always_vuln(orch, args):
        calls["n"] += 1
        return {"verdict": "VULNERABLE", "reason": "boom", "evidence": {}}

    orch = _make_orch({"t": always_vuln})
    orch._is_idempotent_tool = lambda name: True
    budget_calls = {"n": 0}

    def _budget_exceeded():
        budget_calls["n"] += 1
        return budget_calls["n"] > 1

    orch._budget_exceeded = _budget_exceeded
    chain = {"id": "c", "name": "c",
             "trigger": {"mode": "any", "conditions": [{"fact": "framework"}]},
             "steps": [{"id": "s1", "tool": "t"}]}
    orch.add_fact("framework", "generic")
    result = orch.execute_chain(chain)
    step = result["steps"][0]
    assert "confirmation_status" not in step
    assert calls["n"] == 1
