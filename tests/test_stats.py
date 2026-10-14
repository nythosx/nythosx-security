from engine import stats


def test_median_odd():
    assert stats.median([1, 2, 3]) == 2


def test_median_even():
    assert stats.median([1, 2, 3, 4]) == 2.5


def test_median_empty():
    assert stats.median([]) == 0.0


def test_mad_symmetric():
    m = stats.mad([1, 2, 3, 4, 5])
    assert m == 1.0


def test_mad_robust_to_outlier():
    clean = [10, 10, 10, 10, 10]
    dirty = [10, 10, 10, 10, 100000]
    assert stats.mad(clean) == 0.0
    assert stats.mad(dirty) == 0.0


def test_robust_scale():
    s = stats.robust_scale([10, 12, 12, 12, 13, 14])
    assert s > 0


def test_is_outlier_detects_far_value():
    samples = [100, 100, 100, 100, 100, 102, 98]
    assert stats.is_outlier(5000, samples, k=4.0)


def test_is_outlier_rejects_near_value():
    samples = [100, 100, 100, 100, 100, 102, 98]
    assert not stats.is_outlier(105, samples, k=4.0)


def test_mann_whitney_different_distributions():
    a = [10, 11, 12, 11, 10, 12, 11, 10, 12, 11]
    b = [500, 510, 505, 500, 510, 505, 500, 510, 505, 500]
    r = stats.mann_whitney_u(a, b)
    assert r is not None
    assert r["p"] < 0.001
    assert r["z"] > 0 or r["z"] < 0


def test_mann_whitney_same_distribution():
    a = [10, 11, 12, 11, 10, 12, 11, 10, 12, 11]
    b = [11, 12, 10, 11, 12, 10, 11, 12, 10, 11]
    r = stats.mann_whitney_u(a, b)
    assert r is not None
    assert r["p"] > 0.05


def test_mann_whitney_small_sample_returns_none():
    assert stats.mann_whitney_u([1, 2, 3], [4, 5, 6]) is None


def test_payload_is_slower_true():
    baseline = [50, 52, 51, 49, 50, 51, 50, 52]
    payload = [3000, 3050, 2990, 3010, 3020, 3040, 3000, 3030]
    decision, ev = stats.payload_is_slower_than_baseline(baseline, payload)
    assert decision
    assert ev["delta_ms"] > 2000


def test_payload_is_slower_false_by_delta():
    baseline = [50, 52, 51, 49, 50, 51, 50, 52]
    payload = [100, 105, 102, 99, 101, 103, 100, 104]
    decision, ev = stats.payload_is_slower_than_baseline(baseline, payload)
    assert not decision
    assert "delta below" in ev.get("reason", "")


def test_payload_not_significant_when_distributions_overlap():
    # Two samples with interleaved ranks — MW should report p >> 0.05.
    baseline = [100, 500, 150, 450, 200, 400, 250, 350]
    payload = [105, 505, 155, 455, 205, 405, 255, 355]
    decision, ev = stats.payload_is_slower_than_baseline(
        baseline, payload, min_delta_ms=2)
    assert not decision, ev
    assert ev.get("mann_whitney", {}).get("p", 0) > 0.05, ev


def test_payload_is_slower_true_when_cleanly_separated():
    baseline = [50, 52, 51, 49, 50, 51, 50, 52]
    payload = [3000, 3050, 2990, 3010, 3020, 3040, 3000, 3030]
    decision, ev = stats.payload_is_slower_than_baseline(baseline, payload)
    assert decision
    assert ev["mann_whitney"]["p"] < 0.01
