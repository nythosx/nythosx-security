def test_state_conversation_default():
    from engine.state import ScanState
    s = ScanState()
    assert s.conversation == []
    assert s.last_exchange == {}


def test_state_conversation_roundtrip():
    from engine.state import ScanState
    s = ScanState()
    s.conversation.append({"step": "s1", "verdict": "PASS"})
    s.last_exchange = {"step": "s1", "verdict": "PASS"}
    d = s.to_dict()
    assert d["conversation"] == [{"step": "s1", "verdict": "PASS"}]
    assert d["last_exchange"] == {"step": "s1", "verdict": "PASS"}


def test_render_conversation_empty():
    from engine.brains.llm import _render_conversation
    assert _render_conversation([]) == "(none)"
    assert _render_conversation(None) == "(none)"


def test_render_conversation_basic():
    from engine.brains.llm import _render_conversation
    conv = [
        {"step": "s1", "tool": "jwt_attack",
         "verdict": "VULNERABLE", "reason": "alg none accepted",
         "evidence": {"secret": "<redacted>", "status": 200}},
    ]
    out = _render_conversation(conv)
    assert "jwt_attack" in out
    assert "VULNERABLE" in out
    assert "alg none accepted" in out
    assert "evidence keys" in out


def test_render_conversation_respects_limit():
    from engine.brains.llm import _render_conversation
    conv = [
        {"step": f"s{i}", "tool": "t", "verdict": "PASS",
         "reason": f"r{i}"}
        for i in range(30)
    ]
    out = _render_conversation(conv, limit=3)
    assert "s29" in out
    assert "s0" not in out


def test_set_conversation_caps():
    from engine.brains.llm import LLMBrain, _CONVERSATION_LIMIT
    b = LLMBrain(client=lambda p: "{}")
    conv = [{"n": i} for i in range(50)]
    b.set_conversation(conv)
    assert len(b.last_conversation) <= _CONVERSATION_LIMIT * 2
    assert b.last_conversation[-1] == {"n": 49}


def test_set_conversation_ignores_non_list():
    from engine.brains.llm import LLMBrain
    b = LLMBrain(client=lambda p: "{}")
    b.last_conversation = [{"n": 1}]
    b.set_conversation("not-a-list")
    assert b.last_conversation == [{"n": 1}]


def test_redact_evidence_strips_sensitive():
    from engine.chain_engine import _redact_evidence
    ev = {
        "secret": "topsecretvalue",
        "token": "eyJhbGciOi",
        "api_key": "AKIA123",
        "status": 200,
        "body": "a" * 900,
    }
    r = _redact_evidence(ev)
    assert r["secret"] == "<redacted>"
    assert r["token"] == "<redacted>"
    assert r["api_key"] == "<redacted>"
    assert r["status"] == 200
    assert len(r["body"]) <= 403


def test_redact_evidence_handles_nested():
    from engine.chain_engine import _redact_evidence
    ev = {"list": [1, 2, 3], "dict": {"a": 1, "b": 2},
          "none": None}
    r = _redact_evidence(ev)
    assert r["list"].startswith("<list len=3")
    assert r["dict"].startswith("<dict keys=")
    assert r["none"] is None


def test_redact_evidence_non_dict_safe():
    from engine.chain_engine import _redact_evidence
    assert _redact_evidence(None) == {}
    assert _redact_evidence("string") == {}
    assert _redact_evidence([1, 2]) == {}


def test_redact_evidence_caps_keys():
    from engine.chain_engine import _redact_evidence
    ev = {f"k{i}": f"v{i}" for i in range(50)}
    r = _redact_evidence(ev, max_keys=5)
    assert r.get("_truncated") is True
    assert len([k for k in r if k != "_truncated"]) == 5


def test_chain_records_exchange():
    from engine.chain_engine import ChainOrchestrator
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        orch = ChainOrchestrator("http://127.0.0.1",
                                  roe_guard=guard,
                                  max_budget_sec=1)
    except Exception as e:
        import pytest
        pytest.skip(f"orchestrator init failed: {e}")
    orch._record_exchange("c1", {"id": "s1", "tool": "x"}, {
        "verdict": "VULNERABLE", "reason": "test",
        "evidence": {"k": "v"}})
    assert len(orch.state_conversation) == 1
    assert orch.state_conversation[0]["verdict"] == "VULNERABLE"
    assert orch.state_conversation[0]["tool"] == "x"


def test_chain_exchange_caps():
    from engine.chain_engine import ChainOrchestrator
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        orch = ChainOrchestrator("http://127.0.0.1",
                                  roe_guard=guard,
                                  max_budget_sec=1)
    except Exception as e:
        import pytest
        pytest.skip(f"orchestrator init failed: {e}")
    for i in range(100):
        orch._record_exchange(
            "c1", {"id": f"s{i}", "tool": "x"},
            {"verdict": "PASS", "reason": f"r{i}"})
    assert len(orch.state_conversation) == orch.llm_max_conversation
    assert orch.state_conversation[-1]["reason"] == "r99"


def test_chain_exchange_redacts_evidence():
    from engine.chain_engine import ChainOrchestrator
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        orch = ChainOrchestrator("http://127.0.0.1",
                                  roe_guard=guard,
                                  max_budget_sec=1)
    except Exception as e:
        import pytest
        pytest.skip(f"orchestrator init failed: {e}")
    orch._record_exchange(
        "c1", {"id": "s1", "tool": "jwt_attack"},
        {"verdict": "VULNERABLE",
         "reason": "cracked",
         "evidence": {"secret": "hunter2", "status": 200}})
    entry = orch.state_conversation[0]
    assert entry["evidence"]["secret"] == "<redacted>"
    assert entry["evidence"]["status"] == 200


def test_chain_exchange_non_dict_safe():
    from engine.chain_engine import ChainOrchestrator
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        orch = ChainOrchestrator("http://127.0.0.1",
                                  roe_guard=guard,
                                  max_budget_sec=1)
    except Exception as e:
        import pytest
        pytest.skip(f"orchestrator init failed: {e}")
    orch._record_exchange("c1", {"id": "s1", "tool": "x"}, None)
    orch._record_exchange("c1", {"id": "s1", "tool": "x"}, "str")
    assert orch.state_conversation == []


def test_final_report_includes_conversation():
    from engine.chain_engine import ChainOrchestrator
    from engine.roe_guard import ROEGuard
    from engine.config import load_engine
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        orch = ChainOrchestrator("http://127.0.0.1",
                                  roe_guard=guard,
                                  max_budget_sec=1)
    except Exception as e:
        import pytest
        pytest.skip(f"orchestrator init failed: {e}")
    orch._record_exchange(
        "c1", {"id": "s1", "tool": "x"},
        {"verdict": "PASS", "reason": "ok"})
    report = orch._final_report()
    assert "state_conversation" in report
    assert len(report["state_conversation"]) == 1
