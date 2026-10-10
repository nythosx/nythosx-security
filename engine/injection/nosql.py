from __future__ import annotations

import json

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .payloads import NOSQL_PAYLOADS


CAPABILITY = Capability(
    name="nosql_scan",
    description="NoSQL injection via JSON operator injection.",
    category="injection",
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
        with httpx.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(url, json=body, headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:4000]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _baseline(url, headers, timeout, verify, roe_guard):
    body = {"username": "nonexistent_sec_checker_probe",
            "password": "wrong_password_xyz"}
    return _post(url, body, headers, timeout, verify, roe_guard)


_FAIL_MARKERS = ("invalid", "incorrect", "failed", "failure", "unauthorized",
                 "not found", "denied", "wrong", "\"error\"", "'error'",
                 "forbidden", "bad credentials")
_SUCCESS_MARKERS = ("token", "\"success\": true", "\"success\":true",
                    "authenticated", "session", "welcome", "logged in",
                    "jwt", "access_token", "set-cookie")


def _is_failure(resp):
    body = (resp.get("body") or "").lower()
    return any(m in body for m in _FAIL_MARKERS)


def _is_success(resp):
    if not resp or resp.get("status") not in (200, 201, 202):
        return False
    body = (resp.get("body") or "").lower()
    if any(m in body for m in _FAIL_MARKERS):
        return False
    return any(m in body for m in _SUCCESS_MARKERS)


def _looks_bypassed(resp, baseline):
    if not resp or resp.get("status") is None:
        return False
    if resp["status"] not in (200, 201, 202):
        return False
    if not baseline or not _is_failure(baseline):
        return False
    if not _is_success(resp):
        return False
    return (resp.get("body") or "") != (baseline.get("body") or "")


def scan(login_url, headers=None, roe_guard=None, timeout=8,
         username_field="username", password_field="password"):
    verify = _verify_tls()
    baseline = _baseline(login_url, headers, timeout, verify, roe_guard)
    if baseline.get("blocked"):
        return ScanResult(
            capability="nosql_scan", target=login_url,
            verdict="UNKNOWN", reason=baseline["error"],
        )

    attempts = []
    findings = []
    for label, op in NOSQL_PAYLOADS:
        body = {username_field: op, password_field: op}
        r = _post(login_url, body, headers, timeout, verify, roe_guard)
        if r.get("blocked"):
            return ScanResult(
                capability="nosql_scan", target=login_url,
                verdict="UNKNOWN", reason=r["error"],
            )
        attempts.append({"op": label, "status": r.get("status")})
        if _looks_bypassed(r, baseline):
            findings.append({"op": label,
                             "payload": json.dumps(op)})
            break

    if findings:
        return ScanResult(
            capability="nosql_scan", target=login_url,
            verdict="VULNERABLE", severity="high",
            reason=f"NoSQL auth bypass via {findings[0]['op']}",
            evidence={"findings": findings, "attempts": attempts},
        )
    statuses = [a["status"] for a in attempts if a["status"] is not None]
    if not statuses:
        return ScanResult(
            capability="nosql_scan", target=login_url,
            verdict="UNKNOWN", reason="all requests failed",
        )
    return ScanResult(
        capability="nosql_scan", target=login_url,
        verdict="PASS", severity="low",
        reason=f"no NoSQL bypass across {len(attempts)} attempts",
    )


__all__ = ["scan", "CAPABILITY"]
