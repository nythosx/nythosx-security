"""Statistical helpers for timing oracles.

Fixed thresholds produce false positives: a target that answers a sleep
payload in 900ms because it is normally slow at 850ms is not vulnerable.
Fixed thresholds also produce false negatives: a target normally at 50ms
that answers in 900ms with a 1000ms threshold fails to fire.

Robust statistics solve both:

  * MAD (median absolute deviation) is the robust counterpart of stdev.
    One 5-second outlier sample does not pollute the baseline.
  * Mann-Whitney U is a non-parametric test. It compares two samples by
    rank, not by mean, and returns a p-value. If p < 0.05, the payload
    sample is statistically different from the baseline with high
    confidence.

No external dependencies. Normal approximation for p-value (samples >= 8).
"""
from __future__ import annotations

import math


def median(xs):
    if not xs:
        return 0.0
    s = sorted(xs)
    n = len(s)
    if n % 2:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


def mad(xs):
    """Median absolute deviation. Robust replacement for stdev."""
    if not xs:
        return 0.0
    m = median(xs)
    return median([abs(x - m) for x in xs])


def robust_scale(xs):
    """Scale MAD to be comparable to stdev (multiply by 1.4826)."""
    return mad(xs) * 1.4826


def is_outlier(value, samples, k=4.0):
    """True if value is > k * robust_scale from the sample median.

    When scale is 0 (all samples equal, or MAD collapses), fall back to a
    small absolute tolerance so floating-point noise does not register as
    an outlier, while real deviations still do.
    """
    if not samples:
        return False
    m = median(samples)
    s = robust_scale(samples)
    if s == 0:
        tolerance = max(1.0, abs(m) * 0.05)
        return abs(value - m) > tolerance
    return abs(value - m) > k * s


def _normal_cdf(x):
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def mann_whitney_u(a, b):
    """Two-sample Mann-Whitney U test (normal approximation).

    Returns {"U": float, "z": float, "p": float, "n1": int, "n2": int}
    or None if either sample has fewer than 8 items (exact table not
    implemented; normal approximation unreliable below that).
    """
    n1, n2 = len(a), len(b)
    if n1 < 8 or n2 < 8:
        return None
    combined = sorted([(x, 0) for x in a] + [(x, 1) for x in b])
    ranks = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i
        while j < len(combined) and combined[j][0] == combined[i][0]:
            j += 1
        avg = (i + j + 1) / 2.0
        for k in range(i, j):
            ranks[k] = avg
        i = j
    r1 = sum(ranks[k] for k in range(len(combined)) if combined[k][1] == 0)
    u1 = r1 - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    u = min(u1, u2)
    mu = n1 * n2 / 2.0
    sigma = math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12.0)
    if sigma == 0:
        return {"U": u, "z": 0.0, "p": 1.0, "n1": n1, "n2": n2}
    z = (u - mu) / sigma
    p = 2.0 * (1.0 - _normal_cdf(abs(z)))
    return {"U": float(u), "z": float(z), "p": float(p), "n1": n1, "n2": n2}


def payload_is_slower_than_baseline(baseline, payload, p_threshold=0.05,
                                     min_delta_ms=200.0):
    """Return (decision, evidence_dict).

    decision is True when the payload sample is statistically slower than
    the baseline. Falls back to robust-outlier check when samples are too
    small for Mann-Whitney.
    """
    if not baseline or not payload:
        return False, {"reason": "empty sample"}
    b_med = median(baseline)
    p_med = median(payload)
    delta = p_med - b_med
    ev = {
        "baseline_median_ms": round(b_med, 2),
        "payload_median_ms": round(p_med, 2),
        "delta_ms": round(delta, 2),
        "baseline_samples": [round(x, 2) for x in baseline],
        "payload_samples": [round(x, 2) for x in payload],
    }
    if delta < min_delta_ms:
        ev["reason"] = "delta below minimum"
        return False, ev
    mw = mann_whitney_u(baseline, payload)
    if mw is not None:
        ev["mann_whitney"] = mw
        if mw["p"] < p_threshold:
            return True, ev
        ev["reason"] = f"p={mw['p']:.4f} >= {p_threshold}"
        return False, ev
    all_b = list(baseline)
    outliers = [p for p in payload if is_outlier(p, all_b, k=6.0)]
    ev["robust_outliers"] = outliers
    if outliers:
        return True, ev
    ev["reason"] = "small sample, no robust outlier"
    return False, ev


def split_batches(samples, n_batches):
    if not samples or n_batches <= 0:
        return []
    n = len(samples)
    size = max(1, n // n_batches)
    out = []
    for i in range(n_batches):
        start = i * size
        end = n if i == n_batches - 1 else (i + 1) * size
        if start < n:
            out.append(list(samples[start:end]))
    return out


def compare_batches(baseline, candidate, p_threshold=0.05, min_delta_ms=200.0):
    decision, ev = payload_is_slower_than_baseline(
        baseline, candidate, p_threshold=p_threshold,
        min_delta_ms=min_delta_ms)
    return {"signal": decision, "evidence": ev}

__all__ = ["median", "mad", "robust_scale", "is_outlier",
           "mann_whitney_u", "payload_is_slower_than_baseline",
           "split_batches", "compare_batches"]
