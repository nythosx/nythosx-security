import json

from engine.brains.llm import LLMBrain
from engine.brains.rule_based import RuleBasedBrain
from engine.contract import ScanBudget, ScanResult
from engine.orchestrator import Orchestrator
from engine.state import ScanState


def _state():
    return ScanState(
        target="http://example.test",
        framework={"adapter": {"id": "laravel", "name": "Laravel"}, "score": 80},
        discovered_endpoints=["/api/login", "/graphql"],
        budget=ScanBudget(max_iterations=2, max_http_requests=1000),
    )


def test_llm_brain_matches_rules_with_same_capabilities():
    rule = RuleBasedBrain()
    rule_caps = sorted({h.capability for h in rule.propose(_state())})
    assert rule_caps

    def fake_client(prompt):
        return json.dumps({"capabilities": rule_caps})

    llm = LLMBrain(client=fake_client)
    llm_caps = sorted({h.capability for h in llm.propose(_state())})
    assert llm_caps == rule_caps


def test_llm_brain_falls_back_without_client():
    rule = RuleBasedBrain()
    rule_caps = sorted({h.capability for h in rule.propose(_state())})
    llm = LLMBrain(client=None, fallback=rule)
    llm_caps = sorted({h.capability for h in llm.propose(_state())})
    assert llm_caps == rule_caps


def test_llm_brain_falls_back_on_garbage_response():
    rule = RuleBasedBrain()
    rule_caps = sorted({h.capability for h in rule.propose(_state())})

    def fake_client(prompt):
        return "not json at all"

    llm = LLMBrain(client=fake_client, fallback=rule)
    llm_caps = sorted({h.capability for h in llm.propose(_state())})
    assert llm_caps == rule_caps


def test_llm_brain_parses_hypotheses_form():
    def fake_client(prompt):
        return json.dumps({
            "hypotheses": [
                {"capability": "security-headers-missing"},
                {"capability": "cors-wildcard"},
            ]
        })

    llm = LLMBrain(client=fake_client)
    caps = {h.capability for h in llm.propose(_state())}
    assert caps == {"security-headers-missing", "cors-wildcard"}


def test_same_coverage_across_brains():
    rule = RuleBasedBrain()
    rule_caps = sorted({h.capability for h in rule.propose(_state())})

    def fake_client(prompt):
        return json.dumps({"capabilities": rule_caps})

    llm = LLMBrain(client=fake_client)

    def runner(cap, tgt, params):
        return ScanResult(capability=cap, target=tgt, verdict="PASS")

    orc_rule = Orchestrator(runner=runner)
    orc_llm = Orchestrator(runner=runner)
    state_rule = orc_rule.run("http://example.test",
                              initial_state=_state(), brain=rule)
    state_llm = orc_llm.run("http://example.test",
                            initial_state=_state(), brain=llm)
    assert (state_rule.coverage["executed_count"]
            == state_llm.coverage["executed_count"])


def test_brains_share_scanbrain_protocol():
    from engine.brains.base import ScanBrain
    rule = RuleBasedBrain()
    llm = LLMBrain(client=None)
    assert isinstance(rule, ScanBrain)
    assert isinstance(llm, ScanBrain)
