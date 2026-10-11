from engine import iteration


class _FakeState:
    def __init__(self, untested=None, executed=None, target="http://t"):
        self.coverage = {
            "untested_categories": untested or [],
            "owasp": {},
        }
        self.executed_capabilities = set(executed or [])
        self.findings = []
        self.target = target


def _cfg(enabled=True, max_sweeps=3, min_budget_remaining=0.0):
    return {
        "enabled": enabled,
        "max_sweeps": max_sweeps,
        "min_budget_remaining": min_budget_remaining,
    }


def test_should_iterate_disabled():
    state = _FakeState(untested=["A09"])
    assert iteration.should_iterate(state, 0, _cfg(enabled=False)) is False


def test_should_iterate_no_gaps():
    state = _FakeState(untested=[])
    assert iteration.should_iterate(state, 0, _cfg()) is False


def test_should_iterate_with_gaps():
    state = _FakeState(untested=["A09"])
    assert iteration.should_iterate(state, 0, _cfg()) is True


def test_should_iterate_max_sweeps_exhausted():
    state = _FakeState(untested=["A09"])
    assert iteration.should_iterate(state, 3, _cfg(max_sweeps=3)) is False


def test_generate_hypotheses_no_gaps():
    state = _FakeState(untested=[])
    assert iteration.generate_hypotheses(state) == []


def test_generate_hypotheses_returns_list():
    state = _FakeState(untested=["A09", "A03"])
    out = iteration.generate_hypotheses(state)
    assert isinstance(out, list)
    for h in out:
        assert hasattr(h, "capability")
        assert h.source == "coverage_iteration"


def test_generate_hypotheses_skips_executed():
    state = _FakeState(untested=["A03"], executed=["sca-scan"])
    out = iteration.generate_hypotheses(state)
    caps = [h.capability for h in out]
    assert "sca-scan" not in caps


def test_generate_hypotheses_limit():
    state = _FakeState(untested=["A01", "A02", "A05", "A06"])
    out = iteration.generate_hypotheses(state, limit=3)
    assert len(out) <= 3


def test_generate_hypotheses_reason_contains_category():
    state = _FakeState(untested=["A09"])
    out = iteration.generate_hypotheses(state)
    if out:
        assert "A09" in out[0].reason
