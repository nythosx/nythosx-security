import json

from engine.brains.llm import LLMBrain, _new_canary, _UNTRUSTED_OPEN, _UNTRUSTED_CLOSE
from engine.state import ScanState


def test_canary_is_random():
    a = _new_canary()
    b = _new_canary()
    assert a != b
    assert a.startswith("SC_CANARY_")


def test_canary_present_when_client_set():
    brain = LLMBrain(client=lambda p: "{}")
    assert brain._canary is not None


def test_canary_absent_when_client_none():
    brain = LLMBrain(client=None)
    assert brain._canary is None


def test_response_containing_canary_rejected():
    brain = LLMBrain(client=lambda p: "no")
    canary = brain._canary
    leaked = json.dumps({"capabilities": [canary, "jwt-analysis"]})
    caps = brain._parse(leaked)
    assert caps == []


def test_canary_in_prompt_proposal():
    captured = {}

    def client(prompt):
        captured["prompt"] = prompt
        return json.dumps({"capabilities": ["jwt-analysis"]})

    brain = LLMBrain(client=client)
    brain.propose(ScanState(target="https://x"))
    assert brain._canary in captured["prompt"]
    assert _UNTRUSTED_OPEN in captured["prompt"]
    assert _UNTRUSTED_CLOSE in captured["prompt"]


def test_prompt_uses_delimiters():
    captured = {}

    def client(prompt):
        captured["prompt"] = prompt
        return json.dumps({"capabilities": ["jwt-analysis"]})

    brain = LLMBrain(client=client)
    brain.propose(ScanState(target="https://x"))
    p = captured["prompt"]
    assert _UNTRUSTED_OPEN in p
    assert _UNTRUSTED_CLOSE in p
    assert p.index(_UNTRUSTED_OPEN) < p.index(_UNTRUSTED_CLOSE)


def test_user_data_region_has_exactly_one_delimiter_pair():
    captured = {}

    def client(prompt):
        captured["prompt"] = prompt
        return json.dumps({"capabilities": ["jwt-analysis"]})

    brain = LLMBrain(client=client)
    brain.propose(ScanState(target="https://x"))
    p = captured["prompt"]
    user_region = p.split("SESSION_CANARY=", 1)[-1]
    assert user_region.count(_UNTRUSTED_OPEN) == 1
    assert user_region.count(_UNTRUSTED_CLOSE) == 1
    assert user_region.index(_UNTRUSTED_OPEN) < \
           user_region.index(_UNTRUSTED_CLOSE)


def test_allowlist_filters_hallucinated_capabilities():
    brain = LLMBrain(client=lambda p: json.dumps(
        {"capabilities": ["jwt-analysis", "hallucinated-thing"]}),
        capability_allowlist={"jwt-analysis", "cors-wildcard"})
    state = ScanState(target="https://x")
    hyps = brain.propose(state)
    caps = {h.capability for h in hyps}
    assert "jwt-analysis" in caps
    assert "hallucinated-thing" not in caps


def test_no_allowlist_accepts_any_reasonable_capability():
    brain = LLMBrain(client=lambda p: json.dumps(
        {"capabilities": ["custom-capability"]}))
    state = ScanState(target="https://x")
    hyps = brain.propose(state)
    assert "custom-capability" in {h.capability for h in hyps}


def test_long_capabilities_dropped():
    long_name = "x" * 200
    brain = LLMBrain(client=lambda p: json.dumps(
        {"capabilities": [long_name, "jwt-analysis"]}))
    state = ScanState(target="https://x")
    caps = {h.capability for h in brain.propose(state)}
    assert long_name not in caps
    assert "jwt-analysis" in caps


def test_newline_in_capability_dropped():
    brain = LLMBrain(client=lambda p: json.dumps(
        {"capabilities": ["evil\ninjection", "jwt-analysis"]}))
    state = ScanState(target="https://x")
    caps = {h.capability for h in brain.propose(state)}
    assert "evil\ninjection" not in caps
