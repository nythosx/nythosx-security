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
    return o


def _chain():
    return {
        "id": "c", "name": "c",
        "trigger": {"mode": "any", "conditions": [{"fact": "framework"}]},
        "steps": [{"id": "s1", "tool": "t"}],
    }


def test_retry_timeout_stays_timeout():
    def tool(orch, args):
        return {"verdict": "UNKNOWN", "reason": "read timeout", "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain())
    assert len(result["steps"]) == 2
    retry = result["steps"][1]
    assert retry["retried"] is True
    assert retry["unknown_kind"] == "timeout"


def test_unreachable_aborts_without_retry():
    calls = {"n": 0}

    def tool(orch, args):
        calls["n"] += 1
        return {"verdict": "UNKNOWN",
                "reason": "connection refused", "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain())
    assert len(result["steps"]) == 1
    assert result["steps"][0]["unknown_kind"] == "unreachable"
    assert result.get("aborted") is True
    assert result["verdict"] == "UNKNOWN"
    assert calls["n"] == 1, (
        "unreachable must not be retried; retrying a dead target wastes budget"
    )


def test_unreachable_reason_names_the_step():
    def tool(orch, args):
        return {"verdict": "UNKNOWN",
                "reason": "connection refused", "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain())
    assert "s1" in result["reason"]
    assert "could not reach" in result["reason"]


def test_retry_pass_clears_unknown_kind():
    calls = {"n": 0}

    def tool(orch, args):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"verdict": "UNKNOWN", "reason": "read timeout",
                    "evidence": {}}
        return {"verdict": "PASS", "reason": "second try passed",
                "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain())
    assert len(result["steps"]) == 2
    retry = result["steps"][1]
    assert retry["verdict"] == "PASS"
    assert "unknown_kind" not in retry
    assert result.get("reduced_confidence") is not True


def test_retry_timeout_does_not_reduce_confidence():
    def tool(orch, args):
        return {"verdict": "UNKNOWN", "reason": "read timeout", "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain())
    assert result.get("reduced_confidence") is not True
