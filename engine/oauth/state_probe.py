from __future__ import annotations

from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="oauth_state_scan",
    description="OAuth state parameter validation probe.",
    category="auth",
    cost="low",
    destructive=False,
    idempotent=True,
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


def _build(auth_endpoint, state=None):
    p = urlparse(auth_endpoint)
    q = parse_qs(p.query)
    q["response_type"] = ["code"]
    q["client_id"] = ["sec-checker"]
    q["redirect_uri"] = ["https://attacker.example.com/cb"]
    if state is not None:
        q["state"] = [state]
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def scan(auth_endpoint, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()
    findings = []

    url_no_state = _build(auth_endpoint, state=None)
    viol = _roe_block(roe_guard, url_no_state, "GET")
    if viol:
        return ScanResult(
            capability="oauth_state_scan", target=auth_endpoint,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(url_no_state, headers=headers or {})
    except Exception as e:
        return ScanResult(
            capability="oauth_state_scan", target=auth_endpoint,
            verdict="UNKNOWN", reason=f"{type(e).__name__}: {e}",
        )

    if r.status_code in (200, 302, 303, 307):
        loc = r.headers.get("Location", "")
        if "error=invalid_request" not in loc.lower() and "state" not in loc.lower():
            findings.append({"issue": "no_state_not_rejected",
                             "status": r.status_code,
                             "location": loc[:200]})

    url_bad = _build(auth_endpoint, state="x")
    viol = _roe_block(roe_guard, url_bad, "GET")
    if viol:
        return ScanResult(
            capability="oauth_state_scan", target=auth_endpoint,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r2 = c.get(url_bad, headers=headers or {})
    except Exception:
        r2 = None

    if findings:
        return ScanResult(
            capability="oauth_state_scan", target=auth_endpoint,
            verdict="VULNERABLE", severity="high",
            reason="authorization endpoint does not require state parameter",
            evidence={"findings": findings,
                      "no_state_status": r.status_code,
                      "with_state_status": r2.status_code if r2 else None},
        )
    return ScanResult(
        capability="oauth_state_scan", target=auth_endpoint,
        verdict="PASS", severity="low",
        reason="state parameter enforced",
    )


__all__ = ["scan", "CAPABILITY"]
