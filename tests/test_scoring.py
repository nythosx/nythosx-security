from engine.scoring import compute_priority, rank_chains, load_history
from engine.facts import FactStore


def _chain(chain_id="test", priority=100, mode="any", conditions=None,
           framework_hint=None, framework_deny=None, owasp=None):
    c = {
        "id": chain_id,
        "priority": priority,
        "trigger": {"mode": mode, "conditions": conditions or []},
    }
    if framework_hint:
        c["framework_hint"] = framework_hint
    if framework_deny:
        c["framework_deny"] = framework_deny
    if owasp:
        c["owasp_categories"] = owasp
    return c


def _facts(**pairs):
    fs = FactStore()
    for k, v in pairs.items():
        if isinstance(v, tuple):
            fs.add(k, v[0], source=v[1])
        else:
            fs.add(k, v, source="active_probe")
    return fs


def test_unmatched_returns_zero():
    c = _chain(conditions=[{"fact": "has_jwt"}])
    assert compute_priority(c, _facts()) == 0.0


def test_any_single_match_positive():
    c = _chain(priority=100, conditions=[{"fact": "has_jwt"}])
    fs = _facts(has_jwt=True)
    score = compute_priority(c, fs)
    assert score > 0
    assert score <= 100 * 0.9 * 1.5 * 2.0 * 1.5


def test_any_partial_match_reduces_score():
    c_full = _chain(conditions=[{"fact": "a"}, {"fact": "b"}])
    fs_full = _facts(a=True, b=True)
    fs_half = _facts(a=True)
    assert compute_priority(c_full, fs_full) >            compute_priority(c_full, fs_half)


def test_all_requires_every_condition():
    c = _chain(mode="all", conditions=[{"fact": "a"}, {"fact": "b"}])
    assert compute_priority(c, _facts(a=True)) == 0.0


def test_all_matches():
    c = _chain(mode="all", conditions=[{"fact": "a"}, {"fact": "b"}])
    assert compute_priority(c, _facts(a=True, b=True)) > 0


def test_none_mode_with_no_match():
    c = _chain(mode="none", conditions=[{"fact": "a"}])
    assert compute_priority(c, _facts()) > 0


def test_none_mode_with_match_blocks():
    c = _chain(mode="none", conditions=[{"fact": "a"}])
    assert compute_priority(c, _facts(a=True)) == 0.0


def test_condition_value_must_match():
    c = _chain(conditions=[{"fact": "fw", "value": "laravel"}])
    assert compute_priority(c, _facts(fw="django")) == 0.0


def test_condition_value_matches():
    c = _chain(conditions=[{"fact": "fw", "value": "laravel"}])
    assert compute_priority(c, _facts(fw="laravel")) > 0


def test_confidence_affects_score():
    c = _chain(priority=100, conditions=[{"fact": "hint"}])
    fs_low = _facts(hint=("x", "js_match"))
    fs_high = _facts(hint=("x", "live_confirm"))
    assert compute_priority(c, fs_high) > compute_priority(c, fs_low)


def test_weight_affects_score():
    c1 = _chain(priority=100, conditions=[
        {"fact": "low", "weight": 0.1},
        {"fact": "high", "weight": 10.0},
    ])
    c2 = _chain(priority=100, conditions=[
        {"fact": "low", "weight": 10.0},
        {"fact": "high", "weight": 0.1},
    ])
    fs = _facts(low=("v", "js_match"), high=("v", "live_confirm"))
    assert compute_priority(c1, fs) > compute_priority(c2, fs)


def test_framework_hint_boosts():
    c = _chain(conditions=[{"fact": "x"}], framework_hint=["laravel"])
    fs_hit = _facts(x=True, framework="laravel")
    fs_other = _facts(x=True, framework="django")
    assert compute_priority(c, fs_hit) > compute_priority(c, fs_other)


def test_framework_deny_penalizes():
    c = _chain(conditions=[{"fact": "x"}], framework_deny=["wordpress"])
    fs_deny = _facts(x=True, framework="wordpress")
    fs_neutral = _facts(x=True, framework="django")
    assert compute_priority(c, fs_deny) < compute_priority(c, fs_neutral)


def test_coverage_gap_boosts():
    c = _chain(conditions=[{"fact": "x"}], owasp=["A03"])
    fs = _facts(x=True)
    cov_empty = {"owasp": {"A03": {"findings_count": 0}}}
    cov_filled = {"owasp": {"A03": {"findings_count": 5}}}
    assert compute_priority(c, fs, coverage=cov_empty) >            compute_priority(c, fs, coverage=cov_filled)


def test_history_hit_rate_boosts():
    c = _chain(chain_id="jwt-chain", conditions=[{"fact": "x"}])
    fs = _facts(x=True)
    good = {"jwt-chain": {"runs": 10, "vulnerable": 8, "suspicious": 2}}
    bad = {"jwt-chain": {"runs": 10, "vulnerable": 0, "suspicious": 0}}
    assert compute_priority(c, fs, history=good) >            compute_priority(c, fs, history=bad)


def test_history_ignored_when_few_runs():
    c = _chain(chain_id="x", conditions=[{"fact": "y"}])
    fs = _facts(y=True)
    good = {"x": {"runs": 1, "vulnerable": 1}}
    bad = {"x": {"runs": 1, "vulnerable": 0}}
    assert compute_priority(c, fs, history=good) ==            compute_priority(c, fs, history=bad)


def test_rank_chains_sorted_desc():
    c1 = _chain("a", priority=100, conditions=[{"fact": "x"}])
    c2 = _chain("b", priority=50, conditions=[{"fact": "x"}])
    fs = _facts(x=True)
    ranked = rank_chains([c1, c2], fs)
    assert [c["id"] for c in ranked] == ["a", "b"]


def test_rank_chains_filters_zero_score():
    c1 = _chain("a", conditions=[{"fact": "x"}])
    c2 = _chain("b", conditions=[{"fact": "missing"}])
    fs = _facts(x=True)
    ranked = rank_chains([c1, c2], fs)
    assert [c["id"] for c in ranked] == ["a"]


def test_empty_trigger_returns_zero():
    c = _chain(conditions=[])
    assert compute_priority(c, _facts()) == 0.0


def test_missing_fact_store_returns_zero():
    c = _chain(conditions=[{"fact": "x"}])
    assert compute_priority(c, None) == 0.0


def test_load_history_returns_dict():
    h = load_history()
    assert isinstance(h, dict)


def test_compute_priority_accepts_none_chain():
    assert compute_priority(None, _facts()) == 0.0
