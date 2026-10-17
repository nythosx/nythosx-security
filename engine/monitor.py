"""Continuous differential monitor.

Loops hunt() per target, diffs the resulting assets/endpoints/findings
snapshot, and calls on_change(target, diff) whenever anything new
appears. First run only establishes the baseline; diffs start from run 2.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone


def _fact_value(facts, key):
    entry = (facts or {}).get(key)
    if isinstance(entry, dict):
        return entry.get("value")
    return entry


def _snapshot(report):
    facts = report.get("facts") or {}
    recon = report.get("recon") or {}
    return {
        "subdomains": set(_fact_value(facts, "live_subdomains") or []),
        "endpoints": set(recon.get("api_paths") or []),
        "findings": set(
            (f.get("tool"), (f.get("reason") or "")[:80])
            for f in (report.get("findings") or [])
            if isinstance(f, dict)
        ),
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def diff_snapshots(prev, curr):
    if prev is None or "error" in prev:
        return {
            "new_subdomains": sorted(curr["subdomains"]),
            "new_endpoints": sorted(curr["endpoints"]),
            "new_findings": sorted(curr["findings"]),
        }
    return {
        "new_subdomains": sorted(curr["subdomains"] - prev["subdomains"]),
        "new_endpoints": sorted(curr["endpoints"] - prev["endpoints"]),
        "new_findings": sorted(curr["findings"] - prev["findings"]),
    }


def run_monitor(targets, interval_sec=86400, on_change=None, iterations=None,
                hunt_fn=None, hunt_kwargs=None):
    if hunt_fn is None:
        from .hunt import hunt as hunt_fn
    hunt_kwargs = dict(hunt_kwargs or {})
    state = {}
    runs = 0
    while True:
        for t in targets:
            try:
                report = hunt_fn(t, **hunt_kwargs)
            except Exception as e:
                state.setdefault(t, {})["error"] = (
                    f"{type(e).__name__}: {e}")
                continue
            curr = _snapshot(report)
            prev = state.get(t)
            if prev is not None and "error" not in prev:
                diff = diff_snapshots(prev, curr)
                if any(diff.values()) and on_change is not None:
                    try:
                        on_change(t, diff)
                    except Exception:
                        pass
            state[t] = curr
        runs += 1
        if iterations is not None and runs >= iterations:
            return state
        if interval_sec > 0:
            try:
                time.sleep(interval_sec)
            except KeyboardInterrupt:
                return state
