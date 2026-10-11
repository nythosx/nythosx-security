from __future__ import annotations


def _config():
    try:
        from .config import load_engine
        cfg = load_engine() or {}
        return cfg.get("iteration") or {}
    except Exception:
        return {}


def _get_coverage_dict(state):
    cov = getattr(state, "coverage", None)
    if cov is None:
        return {}
    if hasattr(cov, "to_dict"):
        try:
            return cov.to_dict()
        except Exception:
            return {}
    if isinstance(cov, dict):
        return cov
    return {}


def _has_budget(state, min_frac):
    try:
        from . import budget as _budget
        snap = _budget.snapshot()
    except Exception:
        return True

    max_req = snap.get("max_requests")
    if max_req:
        used = int(snap.get("requests") or 0)
        remaining = max(0.0, 1.0 - used / max(1, int(max_req)))
        if remaining < min_frac:
            return False

    max_dur = snap.get("max_duration_seconds")
    started = snap.get("started_at_monotonic")
    if max_dur and started:
        import time as _time
        try:
            elapsed = _time.monotonic() - started
            remaining = max(0.0, 1.0 - elapsed / float(max_dur))
            if remaining < min_frac:
                return False
        except Exception:
            pass

    return True


def should_iterate(state, sweep_count, config=None):
    cfg = config if config is not None else _config()
    if not cfg.get("enabled", False):
        return False
    max_sweeps = int(cfg.get("max_sweeps", 3) or 3)
    if sweep_count >= max_sweeps:
        return False
    min_frac = float(cfg.get("min_budget_remaining", 0.2) or 0.2)
    if not _has_budget(state, min_frac):
        return False
    cov = _get_coverage_dict(state)
    untested = cov.get("untested_categories") or []
    if not untested:
        return False
    return True


def generate_hypotheses(state, limit=10):
    try:
        from .coverage import OWASP_TO_CAPABILITIES
    except Exception:
        return []
    try:
        from .state import Hypothesis
    except Exception:
        return []

    cov = _get_coverage_dict(state)
    untested = cov.get("untested_categories") or []
    if not untested:
        return []

    executed = getattr(state, "executed_capabilities", set()) or set()
    target = getattr(state, "target", "")
    out = []
    seen = set()
    for code in untested:
        for cap in (OWASP_TO_CAPABILITIES.get(code) or []):
            if cap in executed or cap in seen:
                continue
            seen.add(cap)
            out.append(Hypothesis(
                capability=cap,
                target=target,
                reason="coverage gap in " + str(code),
                priority=5,
                source="coverage_iteration",
            ))
            if len(out) >= limit:
                return out
    return out


__all__ = ["should_iterate", "generate_hypotheses"]
