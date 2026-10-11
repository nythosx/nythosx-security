from __future__ import annotations

import time

import httpx

from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


CAPABILITY = Capability(
    name="lockout_probe",
    description=("Detect missing account lockout by sending repeated bad logins "
                 "and checking whether the account is ever locked."),
    category="auth",
    cost="medium",
    destructive=False,
    idempotent=False,
    prerequisites=["known_username"],
    default_on=False,
)


LOCKOUT_MARKERS = ("locked", "too many", "try again later", "account has been",
                   "suspended", "disabled", "rate limit", "too many attempts")


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


def _attempt(login_url, username, password, headers, timeout, verify,
             roe_guard):
    viol = _roe_block(roe_guard, login_url, "POST")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(login_url, json={"email": username, "username": username,
                                         "password": password},
                       headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:1000]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _is_lockout(resp):
    if not resp:
        return False
    st = resp.get("status")
    if st in (423, 429):
        return True
    if st == 403:
        body = (resp.get("body") or "").lower()
        if any(m in body for m in LOCKOUT_MARKERS):
            return True
    body = (resp.get("body") or "").lower()
    return any(m in body for m in LOCKOUT_MARKERS)


def scan(login_url, username, wrong_password="WrongP@ssw0rd_sec_checker!",
         attempts=10, headers=None, roe_guard=None, timeout=8,
         delay_ms=100):
    verify = _verify_tls()
    cfg = (load_engine() or {}).get("weak_password") or {}
    if not cfg.get("enabled", True):
        return ScanResult(
            capability="lockout_probe", target=login_url,
            verdict="UNKNOWN", reason="weak_password.enabled=false",
        )

    responses = []
    for i in range(attempts):
        r = _attempt(login_url, username, wrong_password, headers, timeout,
                     verify, roe_guard)
        if r.get("blocked"):
            return ScanResult(
                capability="lockout_probe", target=login_url,
                verdict="UNKNOWN", reason=r["error"],
            )
        responses.append(r)
        if _is_lockout(r):
            return ScanResult(
                capability="lockout_probe", target=login_url,
                verdict="PASS", severity="medium",
                reason=f"lockout/rate-limit triggered on attempt {i + 1}",
                evidence={"responses": responses[:i + 2],
                          "triggered_at": i + 1},
            )
        if delay_ms:
            time.sleep(delay_ms / 1000.0)

    statuses = [r.get("status") for r in responses]
    real = [s for s in statuses if s is not None]
    if not real:
        return ScanResult(
            capability="lockout_probe", target=login_url,
            verdict="UNKNOWN", reason="all login attempts failed to connect",
        )
    if all(s in (404, 405) for s in real):
        return ScanResult(
            capability="lockout_probe", target=login_url,
            verdict="UNKNOWN", reason="login endpoint not found",
        )
    if all(s == 200 for s in real):
        return ScanResult(
            capability="lockout_probe", target=login_url,
            verdict="SUSPICIOUS", severity="medium",
            reason=(f"login returned 200 for {attempts} consecutive bad "
                    f"credentials (unexpected success response)"),
            evidence={"responses": responses},
        )
    if any(s in (401, 403, 400, 422) for s in real):
        return ScanResult(
            capability="lockout_probe", target=login_url,
            verdict="VULNERABLE", severity="high",
            reason=(f"no lockout/rate-limit after {attempts} consecutive "
                    f"failed logins"),
            evidence={"responses": responses, "attempts": attempts},
        )
    return ScanResult(
        capability="lockout_probe", target=login_url,
        verdict="UNKNOWN", reason=f"unexpected status distribution: {statuses}",
        evidence={"responses": responses},
    )


__all__ = ["scan", "CAPABILITY"]
