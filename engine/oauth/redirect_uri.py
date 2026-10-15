from __future__ import annotations

from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


CAPABILITY = Capability(
    name="oauth_redirect_uri_scan",
    description="OAuth redirect_uri bypass techniques.",
    category="auth",
    cost="medium",
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


BYPASSES = [
    ("suffix_evil", "https://{host}.attacker.example.com"),
    ("prefix_evil", "https://attacker.example.com{host}"),
    ("subdomain_evil", "https://{host}.attacker.example.com/"),
    ("path_escape", "https://{host}/../attacker/"),
    ("backslash", "https://{host}\\@attacker.example.com"),
    ("at_sign", "https://attacker.example.com@{host}"),
    ("userinfo", "https://attacker.example.com%40{host}"),
    ("port_confusion", "https://{host}:attacker.example.com"),
    ("fragment_bypass", "https://{host}#@attacker.example.com"),
    ("scheme_confusion", "https://{host}//attacker.example.com"),
    ("dot_bypass", "https://attacker.example.com.{host}"),
    ("case_mismatch", "HTTPS://{host}"),
]


def _authorize_url(auth_endpoint, redirect_uri):
    p = urlparse(auth_endpoint)
    q = parse_qs(p.query)
    q["response_type"] = ["code"]
    q["client_id"] = ["sec-checker"]
    q["redirect_uri"] = [redirect_uri]
    q["state"] = ["sec_checker_state"]
    q["scope"] = ["openid"]
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def scan(auth_endpoint, target_host=None, headers=None, roe_guard=None,
         timeout=8):
    verify = _verify_tls()
    parsed = urlparse(auth_endpoint)
    host = target_host or parsed.hostname or "target.example.com"

    attempts = []
    findings = []
    for label, template in BYPASSES:
        ru = template.format(host=host)
        url = _authorize_url(auth_endpoint, ru)
        viol = _roe_block(roe_guard, url, "GET")
        if viol:
            return ScanResult(
                capability="oauth_redirect_uri_scan", target=auth_endpoint,
                verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
            )
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.get(url, headers=headers or {})
        except Exception as e:
            attempts.append({"bypass": label, "status": None, "error": str(e)})
            continue
        loc = r.headers.get("Location", "")
        attempts.append({"bypass": label, "status": r.status_code,
                         "location": loc[:200]})
        if "attacker.example.com" in loc:
            findings.append({"bypass": label, "redirect_uri": ru,
                             "location": loc[:200]})

    if findings:
        return ScanResult(
            capability="oauth_redirect_uri_scan", target=auth_endpoint,
            verdict="VULNERABLE", severity="high",
            reason=f"redirect_uri bypass via {findings[0]['bypass']}",
            evidence={"findings": findings, "attempts": attempts},
        )
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="oauth_redirect_uri_scan", target=auth_endpoint,
            verdict="UNKNOWN",
            reason=unreached_reason(attempts),
            evidence={"attempts": attempts[:30]},
        )
    return ScanResult(
        capability="oauth_redirect_uri_scan", target=auth_endpoint,
        verdict="PASS", severity="low",
        reason=f"no redirect_uri bypass across {len(attempts)} attempts",
    )


__all__ = ["scan", "CAPABILITY"]
