from engine.brains.rule_based import RuleBasedBrain
from engine.contract import ScanBudget, ScanResult
from engine.orchestrator import Orchestrator
from engine.state import ScanState


def _state():
    return ScanState(
        target="http://example.test",
        framework={"adapter": {"id": "laravel", "name": "Laravel"}, "score": 80},
        discovered_endpoints=["/api/login", "/api/me", "/graphql"],
        budget=ScanBudget(max_iterations=2, max_http_requests=1000),
    )


def test_rule_based_brain_deterministic():
    brain = RuleBasedBrain()
    a = brain.propose(_state())
    b = brain.propose(_state())
    assert [h.capability for h in a] == [h.capability for h in b]
    assert a


def test_rule_based_brain_hits_laravel_and_graphql():
    brain = RuleBasedBrain()
    caps = {h.capability for h in brain.propose(_state())}
    assert "laravel-debug-mode" in caps
    assert "graphql-deep-security" in caps


def test_orchestrator_same_sequence_across_runs():
    calls_a = []
    calls_b = []

    def runner_a(cap, tgt, params):
        calls_a.append(cap)
        return ScanResult(capability=cap, target=tgt, verdict="PASS")

    def runner_b(cap, tgt, params):
        calls_b.append(cap)
        return ScanResult(capability=cap, target=tgt, verdict="PASS")

    orc_a = Orchestrator(runner=runner_a)
    orc_b = Orchestrator(runner=runner_b)
    orc_a.run("http://example.test", initial_state=_state())
    orc_b.run("http://example.test", initial_state=_state())
    assert calls_a == calls_b
    assert calls_a


def test_orchestrator_records_scanresult_findings():
    def runner(cap, tgt, params):
        return ScanResult(capability=cap, target=tgt, verdict="PASS")

    orc = Orchestrator(runner=runner)
    state = orc.run("http://example.test", initial_state=_state())
    assert state.findings
    for f in state.findings:
        assert isinstance(f, ScanResult)
    assert state.iterations >= 1
    assert state.coverage


def test_orchestrator_marks_visited():
    def runner(cap, tgt, params):
        return ScanResult(capability=cap, target=tgt, verdict="PASS")

    orc = Orchestrator(runner=runner)
    state = orc.run("http://example.test", initial_state=_state())
    assert state.visited
    for cap in state.executed_capabilities:
        assert (cap, state.target) in state.visited
