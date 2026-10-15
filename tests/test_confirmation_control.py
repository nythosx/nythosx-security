import pytest

from engine.chain_engine import ChainOrchestrator


class _Allow:
    def check_url(self, url, method="GET"):
        return True


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)


def _orch(handlers):
    o = ChainOrchestrator("http://test.local", roe_guard=_Allow(),
                          engine_cfg={}, allow_destructive=True)
    o.run_recon = lambda: None
    o._TOOL_HANDLERS = handlers
    o._is_idempotent_tool = lambda name: True
    return o


def _chain(step_extra=None):
    step = {"id": "s1", "tool": "t"}
    if step_extra:
        step.update(step_extra)
    return {
        "id": "c", "name": "c",
        "trigger": {"mode": "any", "conditions": [{"fact": "framework"}]},
        "steps": [step],
    }


def test_retry_vulnerable_confirms():
    calls = {"n": 0}

    def tool(orch, args):
        calls["n"] += 1
        return {"verdict": "VULNERABLE", "reason": "boom", "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain())
    s = result["steps"][0]
    assert s["verdict"] == "VULNERABLE"
    assert s["confirmation_status"] == "confirmed"
    assert calls["n"] == 2


def test_retry_pass_downgrades_to_suspicious():
    calls = {"n": 0}

    def tool(orch, args):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"verdict": "VULNERABLE", "reason": "first",
                    "evidence": {}}
        return {"verdict": "PASS", "reason": "second", "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain())
    s = result["steps"][0]
    assert s["verdict"] == "SUSPICIOUS"
    assert s["confirmation_status"] == "unconfirmed"
    assert "[unconfirmed" in s["reason"]


def test_control_vulnerable_suppresses_finding():
    def tool(orch, args):
        return {"verdict": "VULNERABLE", "reason": "always vulnerable",
                "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    chain = _chain(step_extra={"control_args": {"x": "benign"}})
    result = o.execute_chain(chain)
    s = result["steps"][0]
    assert s["verdict"] == "PASS"
    assert s["confirmation_status"] == "tool_unsound"
    assert "[tool_unsound" in s["reason"]
    assert not any(f.get("step") == "s1" for f in o.findings)


def test_control_pass_then_retry_vulnerable_confirms():
    calls = {"n": 0, "control_seen": False}

    def tool(orch, args):
        if args.get("x") == "benign":
            calls["control_seen"] = True
            return {"verdict": "PASS", "reason": "control pass",
                    "evidence": {}}
        calls["n"] += 1
        return {"verdict": "VULNERABLE", "reason": "boom", "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    chain = _chain(step_extra={"control_args": {"x": "benign"}})
    result = o.execute_chain(chain)
    s = result["steps"][0]
    assert calls["control_seen"]
    assert s["verdict"] == "VULNERABLE"
    assert s["confirmation_status"] == "confirmed"
    assert s["confirmation_control_verdict"] == "PASS"


def test_no_control_args_skips_control():
    def tool(orch, args):
        return {"verdict": "VULNERABLE", "reason": "boom", "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain())
    s = result["steps"][0]
    assert s["verdict"] == "VULNERABLE"
    assert s["confirmation_status"] == "confirmed"
    assert "confirmation_control_verdict" not in s


def test_confirmed_confidence_from_signal_strength():
    def tool(orch, args):
        return {"verdict": "VULNERABLE", "reason": "boom",
                "evidence": {"signal_strength": 0.8}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain())
    s = result["steps"][0]
    assert s["confirmation_status"] == "confirmed"
    assert abs(s["confidence"] - 0.8) < 0.01
