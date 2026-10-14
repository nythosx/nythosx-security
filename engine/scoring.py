from __future__ import annotations

from typing import Any, Optional

DEFAULT_BASE = 50.0
FRAMEWORK_BOOST = 1.5
FRAMEWORK_PENALTY = 0.5
HISTORY_MIN_RUNS = 3
HISTORY_FLOOR = 0.3
HISTORY_CEIL = 2.0
HISTORY_SLOPE = 1.7
COVERAGE_SLOPE = 0.15
COVERAGE_CEIL = 1.5


def _compute_condition_factor(trigger, fact_store):
    if not trigger or not fact_store:
        return False, 0.0
    mode = trigger.get("mode", "any")
    conditions = trigger.get("conditions") or []
    if not conditions:
        return False, 0.0

    matched_flags = []
    matched_confidences = []
    matched_weights = []

    for cond in conditions:
        if not isinstance(cond, dict):
            continue
        key = cond.get("fact")
        if not key:
            continue
        expected = cond.get("value")
        try:
            weight = float(cond.get("weight", 1.0))
        except (TypeError, ValueError):
            weight = 1.0
        if weight <= 0:
            weight = 1.0

        f = fact_store.get_fact(key)
        if f is None:
            matched_flags.append(False)
            continue
        if expected is None:
            matched = True
        else:
            matched = (f.value == expected)
        matched_flags.append(matched)
        if matched:
            matched_confidences.append(f.confidence)
            matched_weights.append(weight)

    total = len(matched_flags)
    if total == 0:
        return False, 0.0
    matched_count = sum(1 for m in matched_flags if m)

    if mode == "all":
        if matched_count < total:
            return False, 0.0
        if not matched_weights:
            return True, 1.0
        total_w = sum(matched_weights)
        avg = sum(c * w for c, w in zip(matched_confidences,
                                         matched_weights)) / total_w
        return True, max(0.0, min(1.0, avg))

    if mode == "any":
        if matched_count == 0:
            return False, 0.0
        total_w = sum(matched_weights)
        if total_w <= 0:
            return True, 0.0
        avg = sum(c * w for c, w in zip(matched_confidences,
                                         matched_weights)) / total_w
        coverage_factor = matched_count / total
        return True, max(0.0, min(1.0, avg * coverage_factor))

    if mode == "none":
        if matched_count > 0:
            return False, 0.0
        return True, 1.0

    return False, 0.0


def _framework_boost(chain, fact_store):
    if not fact_store:
        return 1.0
    hint = chain.get("framework_hint") or []
    deny = chain.get("framework_deny") or []
    if not hint and not deny:
        return 1.0
    fw = fact_store.get("framework")
    if fw is None:
        return 1.0
    fw_name = str(fw).lower()
    for h in hint:
        if str(h).lower() == fw_name:
            return FRAMEWORK_BOOST
    for d in deny:
        if str(d).lower() == fw_name:
            return FRAMEWORK_PENALTY
    return 1.0


def _historical_hit_rate(chain_id, history):
    if not history or not chain_id:
        return 1.0
    stats = history.get(chain_id)
    if not stats:
        return 1.0
    runs = int(stats.get("runs", 0) or 0)
    if runs < HISTORY_MIN_RUNS:
        return 1.0
    vuln = int(stats.get("vulnerable", 0) or 0)
    susp = int(stats.get("suspicious", 0) or 0)
    hit_rate = (vuln + 0.5 * susp) / runs
    mult = HISTORY_FLOOR + hit_rate * HISTORY_SLOPE
    return max(HISTORY_FLOOR, min(HISTORY_CEIL, mult))


def _chain_cost(chain):
    total = 0.0
    for step in (chain or {}).get("steps") or []:
        try:
            from . import cost as _cost
            total += _cost.estimate_cost(step.get("tool", ""))
        except Exception:
            total += 1.0
    return max(1.0, total)


def _cost_factor(chain):
    import math
    c = _chain_cost(chain)
    return 1.0 / math.sqrt(c) if c > 0 else 1.0


def _coverage_gap_weight(chain, coverage):
    if not coverage:
        return 1.0
    cats = chain.get("owasp_categories") or []
    if not cats:
        return 1.0
    owasp_map = (coverage or {}).get("owasp") or {}
    gaps = 0
    for cat in cats:
        info = owasp_map.get(cat)
        if info is None:
            gaps += 1
            continue
        if int(info.get("findings_count", 0) or 0) == 0:
            gaps += 1
    if gaps == 0:
        return 1.0
    weight = 1.0 + COVERAGE_SLOPE * gaps
    return min(COVERAGE_CEIL, weight)


def compute_priority(chain, fact_store=None, history=None, coverage=None):
    if not chain:
        return 0.0
    trigger = chain.get("trigger") or {}
    matched, cond_factor = _compute_condition_factor(trigger, fact_store)
    if not matched:
        return 0.0

    try:
        base = float(chain.get("priority", DEFAULT_BASE))
    except (TypeError, ValueError):
        base = DEFAULT_BASE
    if base <= 0:
        return 0.0

    fw = _framework_boost(chain, fact_store)
    hist = _historical_hit_rate(chain.get("id", ""), history)
    cov = _coverage_gap_weight(chain, coverage)
    costf = _cost_factor(chain)

    score = base * cond_factor * fw * hist * cov * costf
    return float(score)


def rank_chains(chains, fact_store=None, history=None, coverage=None):
    scored = []
    for c in chains or []:
        s = compute_priority(c, fact_store, history, coverage)
        if s > 0:
            scored.append((s, c))
    scored.sort(key=lambda pair: -pair[0])
    return [c for _, c in scored]


def load_history(limit=20):
    try:
        from . import ledger
        stats = ledger.chain_stats(limit=limit)
    except Exception:
        return {}
    out = {}
    for c in (stats.get("chains") or []):
        chain_id = c.get("chain_id")
        if not chain_id:
            continue
        out[chain_id] = {
            "runs": int(c.get("runs", 0) or 0),
            "vulnerable": int(c.get("vulnerable", 0) or 0),
            "suspicious": int(c.get("suspicious", 0) or 0),
            "pass_count": int(c.get("pass_count", 0) or 0),
        }
    return out


__all__ = [
    "compute_priority", "rank_chains", "load_history",
]
