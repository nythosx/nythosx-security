from __future__ import annotations

import re

from ..config import load_engine
from ..contract import Capability, make_result
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="proto_pollution_scan",
    description="Client-side prototype pollution via query string / fragment.",
    category="injection",
    cost="medium",
    destructive=False,
    idempotent=True,
)


POLLUTION_MARKER = "SC_PROTO_9900"

PAYLOADS = [
    ("__proto__", "__proto__[SC_PROTO_9900]=" + POLLUTION_MARKER),
    ("constructor.prototype", "constructor[prototype][SC_PROTO_9900]=" + POLLUTION_MARKER),
    ("__proto__.innerHTML", "__proto__[innerHTML]=<img src=x onerror=alert('" + POLLUTION_MARKER + "')>"),
    ("__proto__.src", "__proto__[src]=data:,alert('" + POLLUTION_MARKER + "')"),
]

DETECTION_REGEX = re.compile(re.escape(POLLUTION_MARKER))


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


def _build_url(base, qs):
    sep = "&" if "?" in base else "?"
    return base + sep + qs


def _fetch(url, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(url, headers=headers or {})
        return {"status": r.status_code, "body": r.text or "",
                "headers": dict(r.headers)}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def scan(target_url, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()
    baseline = _fetch(target_url, headers, timeout, verify, roe_guard)
    if baseline.get("blocked"):
        return make_result(
            {"verdict": "UNKNOWN", "reason": baseline["error"]},
            capability="proto_pollution_scan", args=(target_url,))
    if baseline.get("status") is None:
        return make_result(
            {"verdict": "UNKNOWN",
             "reason": f"baseline fetch failed: {baseline.get('error')}"},
            capability="proto_pollution_scan", args=(target_url,))

    attempts = []
    findings = []
    for label, qs in PAYLOADS:
        url = _build_url(target_url, qs)
        r = _fetch(url, headers, timeout, verify, roe_guard)
        if r.get("blocked"):
            return make_result(
                {"verdict": "UNKNOWN", "reason": r["error"]},
                capability="proto_pollution_scan", args=(target_url,))
        body = r.get("body") or ""
        reflected = DETECTION_REGEX.search(body) is not None
        attempts.append({
            "label": label, "status": r.get("status"),
            "reflected": reflected,
            "delta_len": len(body) - len(baseline.get("body") or ""),
        })
        if reflected:
            findings.append({
                "label": label, "payload": qs,
                "preview": body[:300],
            })

    if findings:
        return make_result({
            "verdict": "SUSPICIOUS",
            "reason": f"pollution payload reflected in response "
                      f"({findings[0]['label']}) — manual confirmation "
                      f"required",
            "evidence": {"findings": findings, "attempts": attempts},
        }, capability="proto_pollution_scan", args=(target_url,))

    return make_result({
        "verdict": "PASS",
        "reason": "no prototype pollution reflection",
        "evidence": {"attempts": attempts},
    }, capability="proto_pollution_scan", args=(target_url,))


__all__ = ["scan", "PAYLOADS", "CAPABILITY"]
