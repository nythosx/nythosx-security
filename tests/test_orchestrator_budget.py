import time

from engine.contract import ScanBudget, ScanResult
from engine.orchestrator import Orchestrator
from engine.state import Hypothesis, ScanState


class CountingRunner:
    def __init__(self, cost_per_call=1):
        self.calls = 0
        self.cost_per_call = cost_per_call

    def __call__(self, cap, tgt, params):
        self.calls += 1
        return ScanResult(capability=cap, target=tgt, verdict="PASS",
                          cost_used={"http_requests": self.cost_per_call})


class CyclingBrain:
    def __init__(self, per_iter=10):
        self.per_iter = per_iter

    def propose(self, state):
        return [Hypothesis(capability=f"cyc_{i}", target=state.target)
                for i in range(self.per_iter)]

    def triage(self, finding):
        return None

    def should_stop(self, state):
        return False

    def can_author_payload(self, capability):
        return False

    def propose_payload(self, state, capability):
        return None


def _state(budget):
    return ScanState(
        target="http://example.test",
        framework={"adapter": {"id": "laravel"}},
        budget=budget,
    )


def test_max_iterations_enforced():
    budget = ScanBudget(max_iterations=3, max_http_requests=100000,
                        max_duration_seconds=1000.0)
    brain = CyclingBrain(per_iter=2)
    orc = Orchestrator(runner=CountingRunner(), brain=brain)
    state = orc.run("http://example.test", initial_state=_state(budget))
    assert state.iterations <= 3


def test_max_http_requests_enforced():
    budget = ScanBudget(max_iterations=100, max_http_requests=5,
                        max_duration_seconds=1000.0)
    runner = CountingRunner(cost_per_call=2)
    brain = CyclingBrain(per_iter=10)
    orc = Orchestrator(runner=runner, brain=brain)
    state = orc.run("http://example.test", initial_state=_state(budget))
    total_http = sum(
        (getattr(f, "cost_used", {}) or {}).get("http_requests", 0)
        for f in state.findings
    )
    assert total_http >= 5


def test_max_duration_enforced():
    budget = ScanBudget(max_iterations=100, max_http_requests=100000,
                        max_duration_seconds=0.001)
    brain = CyclingBrain(per_iter=5)
    orc = Orchestrator(runner=CountingRunner(), brain=brain)
    t0 = time.perf_counter()
    orc.run("http://example.test", initial_state=_state(budget))
    elapsed = time.perf_counter() - t0
    assert elapsed < 3.0


def test_max_hypotheses_per_iter_enforced():
    budget = ScanBudget(max_iterations=1, max_http_requests=100000,
                        max_duration_seconds=1000.0,
                        max_hypotheses_per_iter=3)
    runner = CountingRunner()
    brain = CyclingBrain(per_iter=50)
    orc = Orchestrator(runner=runner, brain=brain)
    orc.run("http://example.test", initial_state=_state(budget))
    assert runner.calls <= 3


def test_convergence_stops_loop():
    budget = ScanBudget(max_iterations=50, max_http_requests=100000,
                        max_duration_seconds=1000.0, convergence_window=1)
    brain = CyclingBrain(per_iter=1)
    orc = Orchestrator(runner=CountingRunner(), brain=brain)
    state = orc.run("http://example.test", initial_state=_state(budget))
    assert state.iterations < 50
