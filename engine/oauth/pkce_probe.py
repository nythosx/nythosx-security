from __future__ import annotations

from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


CAPABILITY = Capability(
    name="oauth_pkce_scan",
    description="PKCE downgrade / absence probe.",
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


def _build(auth_endpoint, code_challenge=None, method=None):
    p = urlparse(auth_endpoint)
    q = parse_qs(p.query)
    q["response_type"] = ["code"]
    q["client_id"] = ["sec-checker"]
    q["redirect_uri"] = ["https://attacker.example.com/cb"]
    q["state"] = ["state123"]
    if code_challenge is not None:
        q["code_challenge"] = [code_challenge]
    if method is not None:
        q["code_challenge_method"] = [method]
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def scan(auth_endpoint, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()

    no_pkce = _build(auth_endpoint)
    viol = _roe_block(roe_guard, no_pkce, "GET")
    if viol:
        return ScanResult(
            capability="oauth_pkce_scan", target=auth_endpoint,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r_no = c.get(no_pkce, headers=headers or {})
    except Exception as e:
        return ScanResult(
            capability="oauth_pkce_scan", target=auth_endpoint,
            verdict="UNKNOWN", reason=f"{type(e).__name__}: {e}",
        )

    plain = _build(auth_endpoint, code_challenge="simple_challenge",
                    method="plain")
    viol = _roe_block(roe_guard, plain, "GET")
    if viol:
        return ScanResult(
            capability="oauth_pkce_scan", target=auth_endpoint,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r_plain = c.get(plain, headers=headers or {})
    except Exception:
        r_plain = None

    findings = []
    if r_no.status_code in (200, 302, 303, 307):
        loc = r_no.headers.get("Location", "")
        if "error=" not in loc.lower():
            findings.append({"issue": "no_pkce_accepted",
                             "status": r_no.status_code})
    if r_plain and r_plain.status_code in (200, 302, 303, 307):
        loc = r_plain.headers.get("Location", "")
        if "error=invalid_request" not in loc.lower():
            findings.append({"issue": "plain_challenge_accepted",
                             "status": r_plain.status_code})

    if any(f["issue"] == "plain_challenge_accepted" for f in findings):
        return ScanResult(
            capability="oauth_pkce_scan", target=auth_endpoint,
            verdict="SUSPICIOUS", severity="medium",
            reason="PKCE code_challenge_method=plain accepted",
            evidence={"findings": findings},
        )
    if any(f["issue"] == "no_pkce_accepted" for f in findings):
        return ScanResult(
            capability="oauth_pkce_scan", target=auth_endpoint,
            verdict="SUSPICIOUS", severity="low",
            reason="PKCE not required (authorization proceeds without it)",
            evidence={"findings": findings},
        )
    if r_no.status_code in (404, 410):
        return ScanResult(
            capability="oauth_pkce_scan", target=auth_endpoint,
            verdict="UNKNOWN",
            reason=(f"authorization endpoint returned {r_no.status_code} — "
                    f"endpoint not found"),
            evidence={"status": r_no.status_code},
        )
    return ScanResult(
        capability="oauth_pkce_scan", target=auth_endpoint,
        verdict="PASS", severity="info",
        reason="PKCE appears enforced",
    )


__all__ = ["scan", "CAPABILITY"]
