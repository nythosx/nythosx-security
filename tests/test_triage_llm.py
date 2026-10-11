import json

from engine.brains.base import ScanBrain
from engine.brains.llm import LLMBrain
from engine.brains.rule_based import RuleBasedBrain
from engine.state import TriageDecision
from engine.diff import BaselineSnapshot


def _baseline(status=200, body='{"id":1}', timing=100.0):
    return BaselineSnapshot(
        url="http://t/x", method="GET", status=status,
        body=body, body_len=len(body),
        timing_samples=[timing, timing, timing],
        structural_hash="abc123",
    )


def test_rule_based_has_triage_response():
    brain = RuleBasedBrain()
    assert hasattr(brain, "triage_response")
    r = brain.triage_response(_baseline(), {"status": 200, "body_len": 8})
    assert isinstance(r, TriageDecision)


def test_rule_based_status_shift_escalates():
    brain = RuleBasedBrain()
    r = brain.triage_response(_baseline(status=200),
                              {"status": 500, "body_len": 8})
    assert r.escalate is True
    assert "status" in r.reason


def test_rule_based_length_delta_escalates():
    brain = RuleBasedBrain()
    r = brain.triage_response(_baseline(body='{"x":1}'),
                              {"status": 200, "body_len": 500})
    assert r.escalate is True


def test_rule_based_identical_does_not_escalate():
    brain = RuleBasedBrain()
    b = _baseline(body='{"id":1}')
    r = brain.triage_response(b, {"status": 200, "body_len": b.body_len})
    assert r.escalate is False


def test_rule_based_none_inputs_safe():
    brain = RuleBasedBrain()
    r = brain.triage_response(None, None)
    assert isinstance(r, TriageDecision)
    assert r.keep is True


def test_llm_brain_falls_back_without_client():
    brain = LLMBrain(client=None, fallback=RuleBasedBrain())
    r = brain.triage_response(_baseline(), {"status": 500, "body_len": 8})
    assert r.escalate is True


def test_llm_brain_parses_meaningful_true():
    def fake(prompt):
        return json.dumps({"meaningful": True, "confidence": 0.9,
                           "reasoning": "status shifted"})
    brain = LLMBrain(client=fake)
    r = brain.triage_response(_baseline(), {"status": 500, "body_len": 8})
    assert r.escalate is True
    assert "status" in r.reason


def test_llm_brain_parses_meaningful_false():
    def fake(prompt):
        return json.dumps({"meaningful": False, "confidence": 0.8,
                           "reasoning": "noise only"})
    brain = LLMBrain(client=fake)
    r = brain.triage_response(_baseline(), {"status": 200, "body_len": 8})
    assert r.escalate is False


def test_llm_brain_handles_malformed_json():
    def fake(prompt):
        return "not json at all"
    brain = LLMBrain(client=fake, fallback=RuleBasedBrain())
    r = brain.triage_response(_baseline(status=200),
                              {"status": 500, "body_len": 8})
    assert isinstance(r, TriageDecision)


def test_llm_brain_handles_fenced_json():
    def fake(prompt):
        return '```json\n{"meaningful": true, "confidence": 0.9, "reasoning": "x"}\n```'
    brain = LLMBrain(client=fake)
    r = brain.triage_response(_baseline(), {"status": 500, "body_len": 8})
    assert r.escalate is True


def test_llm_brain_falls_back_on_client_exception():
    def boom(prompt):
        raise RuntimeError("network error")
    brain = LLMBrain(client=boom, fallback=RuleBasedBrain())
    r = brain.triage_response(_baseline(status=200),
                              {"status": 500, "body_len": 8})
    assert isinstance(r, TriageDecision)
    assert r.escalate is True


def test_llm_brain_clamps_confidence():
    def fake(prompt):
        return json.dumps({"meaningful": True, "confidence": 5.0,
                           "reasoning": "x"})
    brain = LLMBrain(client=fake)
    r = brain.triage_response(_baseline(), {"status": 500, "body_len": 8})
    assert r.escalate is True


def test_scanbrain_protocol_has_triage_response():
    assert hasattr(ScanBrain, "triage_response")


def test_both_brains_satisfy_protocol():
    assert isinstance(RuleBasedBrain(), ScanBrain)
    assert isinstance(LLMBrain(client=None), ScanBrain)


def test_llm_brain_accepts_dict_inputs():
    def fake(prompt):
        return json.dumps({"meaningful": True, "confidence": 0.7,
                           "reasoning": "structural"})
    brain = LLMBrain(client=fake)
    r = brain.triage_response(
        {"status": 200, "body_len": 100, "structural_hash": "aaa"},
        {"status": 200, "body_len": 100, "structural_hash": "bbb"},
    )
    assert r.escalate is True
