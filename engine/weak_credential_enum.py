from __future__ import annotations

import time
from pathlib import Path

import httpx

from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


CAPABILITY = Capability(
    name="weak_credential_enum",
    description=("Attempt a small curated list of common credentials against a "
                 "login endpoint. Requires explicit written authorization."),
    category="auth",
    cost="high",
    destructive=True,
    idempotent=False,
    prerequisites=["written_authorization"],
    default_on=False,
)


_ROE_DIR = Path(__file__).parent.parent / "wordlists"
_WEAK_PW_FILE = _ROE_DIR / "weak_passwords_top100.txt"
_DEFAULT_USERNAMES = ["admin", "administrator", "root", "test", "user",
                      "guest", "demo", "service"]


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


def _load_passwords(limit=20):
    if not _WEAK_PW_FILE.exists():
        return ["password", "123456", "admin"]
    lines = [l.strip() for l in _WEAK_PW_FILE.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.startswith("#")]
    return lines[:limit]


def _attempt(login_url, username, password, headers, timeout, verify,
             roe_guard):
    viol = _roe_block(roe_guard, login_url, "POST")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(login_url,
                       json={"email": username, "username": username,
                             "password": password},
                       headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:1000]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _looks_success(resp):
    if not resp or resp.get("status") not in (200, 201, 202):
        return False
    body = (resp.get("body") or "").lower()
    for marker in ("invalid", "incorrect", "wrong password", "authentication failed",
                    "bad credentials", "unauthorized"):
        if marker in body:
            return False
    for marker in ("token", "session", "success", "welcome", "logged in"):
        if marker in body:
            return True
    return True


def scan(login_url, usernames=None, headers=None, roe_guard=None,
         timeout=8, max_passwords=20, delay_ms=150):
    verify = _verify_tls()
    cfg = (load_engine() or {}).get("weak_password") or {}
    if not cfg.get("opt_in_destructive", False):
        return ScanResult(
            capability="weak_credential_enum", target=login_url,
            verdict="UNKNOWN",
            reason=("destructive credential enumeration disabled "
                    "(set weak_password.opt_in_destructive: true in engine.yaml)"),
        )

    usernames = usernames or _DEFAULT_USERNAMES
    passwords = _load_passwords(max_passwords)

    attempts = []
    hits = []
    for user in usernames:
        for pw in passwords:
            r = _attempt(login_url, user, pw, headers, timeout, verify,
                         roe_guard)
            if r.get("blocked"):
                return ScanResult(
                    capability="weak_credential_enum", target=login_url,
                    verdict="UNKNOWN", reason=r["error"],
                )
            attempts.append({"username": user, "password_len": len(pw),
                             "status": r.get("status")})
            if _looks_success(r):
                hits.append({"username": user, "password": pw})
                break
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
        if hits:
            break

    if hits:
        return ScanResult(
            capability="weak_credential_enum", target=login_url,
            verdict="VULNERABLE", severity="critical",
            reason=(f"weak credential accepted for user '{hits[0]['username']}'"),
            evidence={"hits": hits, "attempts": len(attempts)},
        )
    if not attempts:
        return ScanResult(
            capability="weak_credential_enum", target=login_url,
            verdict="UNKNOWN", reason="no attempts made",
        )
    return ScanResult(
        capability="weak_credential_enum", target=login_url,
        verdict="PASS", severity="info",
        reason=f"no weak credentials accepted across {len(attempts)} attempts",
        evidence={"attempts": len(attempts)},
    )


__all__ = ["scan", "CAPABILITY"]
