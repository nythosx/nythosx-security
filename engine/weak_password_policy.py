from __future__ import annotations

import json
import time

import httpx

from .config import load_engine
from .contract import Capability, ScanResult, make_result
from .roe_guard import ROEGuard, ROEViolation


CAPABILITY = Capability(
    name="weak_password_scan",
    description=("Test the account password policy by attempting to change the "
                 "authenticated user's password to a set of weak values."),
    category="auth",
    cost="medium",
    destructive=False,
    idempotent=False,
    prerequisites=["known_username"],
    default_on=True,
)


WEAK_PASSWORDS = [
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "password1",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "a",
    "aa",
    "aaa",
]


DEFAULT_CHANGE_PATHS = [
    "/api/password/change",
    "/api/user/password",
    "/api/account/password",
    "/api/me/password",
    "/api/users/me/password",
    "/user/password",
    "/account/password",
    "/settings/password",
]


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
        return {"url": url, "blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with httpx.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(url, json=body, headers=headers or {})
        return {"url": url, "status": r.status_code,
                "body": (r.text or "")[:2000]}
    except Exception as e:
        return {"url": url, "status": None, "error": f"{type(e).__name__}: {e}"}


def _looks_accepted(resp):
    if not resp or resp.get("status") is None:
        return False
    if resp["status"] not in (200, 201, 202, 204):
        return False
    body = (resp.get("body") or "").lower()
    if not body:
        return True
    if any(m in body for m in ("error", "invalid", "reject", "too weak",
                                "too short", "must be at least",
                                "does not meet", "policy")):
        return False
    return True


def scan(target_url, headers=None, roe_guard=None, change_path=None,
         current_password=None, current_password_field="current_password",
         new_password_field="new_password", timeout=8):
    verify = _verify_tls()
    adapter_cfg = (load_engine() or {}).get("weak_password") or {}
    if not adapter_cfg.get("enabled", True):
        return ScanResult(
            capability="weak_password_scan", target=target_url,
            verdict="UNKNOWN", reason="weak_password.enabled=false",
        )

    base = target_url.rstrip("/")
    paths = [change_path] if change_path else DEFAULT_CHANGE_PATHS

    attempts = []
    findings = []
    for path in paths:
        url = base + (path if path.startswith("/") else "/" + path)
        for pw in WEAK_PASSWORDS:
            body = {new_password_field: pw}
            if current_password is not None:
                body[current_password_field] = current_password
            r = _post(url, body, headers, timeout, verify, roe_guard)
            entry = {"path": path, "password": pw, "status": r.get("status")}
            attempts.append(entry)
            if r.get("blocked"):
                return ScanResult(
                    capability="weak_password_scan", target=target_url,
                    verdict="UNKNOWN", reason=r["error"],
                )
            if _looks_accepted(r):
                findings.append({"path": path, "password": pw,
                                 "status": r["status"]})
                break
        if findings:
            break

    if findings:
        return ScanResult(
            capability="weak_password_scan", target=target_url,
            verdict="VULNERABLE", severity="high",
            reason=(f"password policy accepted weak value '{findings[0]['password']}' "
                    f"at {findings[0]['path']}"),
            evidence={"findings": findings, "attempts": attempts[:20]},
        )
    if not attempts:
        return ScanResult(
            capability="weak_password_scan", target=target_url,
            verdict="UNKNOWN", reason="no attempts made",
        )
    statuses = [a["status"] for a in attempts if a["status"] is not None]
    if not statuses:
        return ScanResult(
            capability="weak_password_scan", target=target_url,
            verdict="UNKNOWN", reason="all requests failed",
        )
    if all(s in (404, 405) for s in statuses):
        return ScanResult(
            capability="weak_password_scan", target=target_url,
            verdict="UNKNOWN",
            reason="no password change endpoint found",
        )
    if all(s in (401, 403) for s in statuses):
        return ScanResult(
            capability="weak_password_scan", target=target_url,
            verdict="UNKNOWN",
            reason="authentication required for password change",
        )
    return ScanResult(
        capability="weak_password_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"weak passwords rejected across {len(attempts)} attempts",
        evidence={"attempts": attempts[:20]},
    )


__all__ = ["scan", "CAPABILITY", "WEAK_PASSWORDS"]
