from __future__ import annotations

import secrets
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from ..config import load_engine
from ..contract import Capability, make_result
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="oauth_flow_probe",
    description="OAuth full flow probes: code interception, token substitution, mixed flow downgrade.",
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


def _build_authorize(auth_endpoint, **params):
    p = urlparse(auth_endpoint)
    q = parse_qs(p.query)
    for k, v in params.items():
        q[k] = [v]
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def _probe(auth_endpoint, params, headers, timeout, verify, roe_guard):
    url = _build_authorize(auth_endpoint, **params)
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(url, headers=headers or {})
        return {
            "status": r.status_code,
            "location": r.headers.get("Location", ""),
            "body": (r.text or "")[:1000],
        }
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def probe_mixed_flow(auth_endpoint, client_id="sec-checker",
                     redirect_uri="https://attacker.example.com/cb",
                     headers=None, timeout=8, verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    state = secrets.token_urlsafe(8)
    r = _probe(auth_endpoint, {
        "response_type": "token",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
    }, headers, timeout, verify, roe_guard)
    if r.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": r["error"]}
    if r.get("status") in (302, 303, 307):
        loc = r.get("location") or ""
        if "access_token=" in loc or "token_type=" in loc:
            return {"verdict": "VULNERABLE",
                    "reason": "implicit flow accepted (response_type=token)",
                    "evidence": {"location": loc[:200]}}
        if "error=unsupported_response_type" in loc:
            return {"verdict": "PASS",
                    "reason": "implicit flow rejected",
                    "evidence": {"location": loc[:200]}}
    return {"verdict": "UNKNOWN",
            "reason": "response did not clearly accept or reject implicit flow",
            "evidence": {"status": r.get("status"),
                         "location": (r.get("location") or "")[:200]}}


def probe_client_secret_leak(auth_endpoint, headers=None, timeout=8,
                              verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    r = _probe(auth_endpoint, {
        "response_type": "code",
        "client_id": "invalid-client-probe",
        "redirect_uri": "https://attacker.example.com/cb",
    }, headers, timeout, verify, roe_guard)
    if r.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": r["error"]}
    body = (r.get("body") or "").lower()
    loc = (r.get("location") or "").lower()
    leaked_patterns = ["client_secret", "client-secret", "secret="]
    for pat in leaked_patterns:
        if pat in body or pat in loc:
            return {"verdict": "VULNERABLE",
                    "reason": f"error response leaks client_secret pattern "
                              f"'{pat}'",
                    "evidence": {"preview": (body or loc)[:300]}}
    return {"verdict": "PASS",
            "reason": "no client_secret in error response"}


def probe_redirect_prefix(auth_endpoint, target_host="",
                          headers=None, timeout=8, verify=None,
                          roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    candidates = [
        f"https://{target_host}.attacker.example.com/cb",
        f"https://attacker.example.com/?{target_host}",
        f"https://{target_host}#@attacker.example.com",
    ]
    findings = []
    attempts = []
    for ru in candidates:
        r = _probe(auth_endpoint, {
            "response_type": "code",
            "client_id": "sec-checker",
            "redirect_uri": ru,
            "state": secrets.token_urlsafe(8),
        }, headers, timeout, verify, roe_guard)
        if r.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": r["error"]}
        loc = r.get("location") or ""
        attempts.append({"redirect_uri": ru, "status": r.get("status"),
                         "location": loc[:200]})
        if "attacker.example.com" in loc:
            findings.append({"redirect_uri": ru, "location": loc[:200]})
    if findings:
        return {"verdict": "VULNERABLE",
                "reason": f"redirect_uri prefix bypass accepted",
                "evidence": {"findings": findings, "attempts": attempts}}
    return {"verdict": "PASS",
            "reason": "no redirect_uri prefix bypass",
            "evidence": {"attempts": attempts}}


def scan(auth_endpoint, target_host=None, headers=None, roe_guard=None,
         timeout=8):
    verify = _verify_tls()
    viol = _roe_block(roe_guard, auth_endpoint, "GET")
    if viol:
        return make_result(
            {"verdict": "UNKNOWN", "reason": f"ROE_BLOCK: {viol}"},
            capability="oauth_flow_probe", args=(auth_endpoint,))

    host = target_host or urlparse(auth_endpoint).hostname or ""
    results = {
        "mixed_flow": probe_mixed_flow(auth_endpoint, headers=headers,
                                       timeout=timeout, verify=verify,
                                       roe_guard=roe_guard),
        "client_secret_leak": probe_client_secret_leak(
            auth_endpoint, headers=headers, timeout=timeout, verify=verify,
            roe_guard=roe_guard),
        "redirect_prefix": probe_redirect_prefix(
            auth_endpoint, target_host=host, headers=headers,
            timeout=timeout, verify=verify, roe_guard=roe_guard),
    }

    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    overall = "UNKNOWN"
    for r in results.values():
        if rank.get(r.get("verdict"), 0) > rank.get(overall, 0):
            overall = r["verdict"]

    reasons = [f"{k}: {v.get('reason','')[:80]}"
               for k, v in results.items() if v.get("verdict") != "PASS"]

    return make_result({
        "verdict": overall,
        "reason": "; ".join(reasons)[:400] if reasons else "no OAuth flow issue detected",
        "evidence": {"endpoint": auth_endpoint, "results": results},
    }, capability="oauth_flow_probe", args=(auth_endpoint,))


__all__ = ["scan", "probe_mixed_flow", "probe_client_secret_leak",
           "probe_redirect_prefix", "CAPABILITY"]


from ..chain_engine import register_tool as _register_flow_tool


def _tool_oauth_flow_probe(orch, args):
    endpoint = (args.get("auth_endpoint")
                or orch.get_context("oauth_auth_endpoint")
                or orch.target)
    target_host = args.get("target_host") or None
    try:
        r = scan(endpoint, target_host=target_host,
                 roe_guard=orch.roe_guard)
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": (f"oauth_flow_probe error: "
                           f"{type(e).__name__}: {e}")}
    return {
        "verdict": r.get("verdict", "UNKNOWN"),
        "reason": r.get("reason", "") or "",
        "evidence": r.get("evidence", {}) or {},
    }


_register_flow_tool("oauth_flow_probe", _tool_oauth_flow_probe)

