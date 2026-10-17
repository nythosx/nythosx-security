from __future__ import annotations

from urllib.parse import urlparse

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


CAPABILITY = Capability(
    name="password_reset_scan",
    description="Password reset poisoning via Host header injection.",
    category="injection",
    cost="low",
    destructive=False,
    idempotent=True,
)

RESET_PATHS = [
    "/forgot", "/forgot-password", "/password/forgot",
    "/password/reset", "/auth/forgot", "/auth/password/forgot",
    "/api/password/forgot", "/api/auth/forgot", "/reset", "/reset-password",
]

INJECT_HEADERS = [
    ("X-Forwarded-Host", "evil-reset.example.com"),
    ("X-Forwarded-For", "evil-reset.example.com"),
    ("X-Forwarded-Server", "evil-reset.example.com"),
    ("X-Host", "evil-reset.example.com"),
    ("X-Original-URL", "evil-reset.example.com"),
    ("Host", "evil-reset.example.com"),
    ("Referer", "http://evil-reset.example.com/reset"),
]

POISON_MARKER = "evil-reset.example.com"


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


def _find_reset_endpoint(base_url, headers, timeout, verify, roe_guard):
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in RESET_PATHS:
        url = origin + path
        if _roe_block(roe_guard, url, "GET"):
            continue
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.get(url, headers=headers or {})
        except Exception:
            continue
        if r.status_code in (200, 201, 405):
            return url
    return None


def scan(base_url, email="test@example.com", headers=None, roe_guard=None,
         timeout=10):
    verify = _verify_tls()
    reset_url = _find_reset_endpoint(base_url, headers, timeout, verify,
                                      roe_guard)
    if not reset_url:
        return ScanResult(
            capability="password_reset_scan", target=base_url,
            verdict="UNKNOWN",
            reason="no password reset endpoint discovered",
        )
    attempts = []
    findings = []
    for hname, hval in INJECT_HEADERS:
        h = dict(headers or {})
        h[hname] = hval
        viol = _roe_block(roe_guard, reset_url, "POST")
        if viol:
            return ScanResult(
                capability="password_reset_scan", target=reset_url,
                verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
            )
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.post(reset_url, json={"email": email}, headers=h)
        except Exception as e:
            attempts.append({"header": hname, "error": str(e)[:120]})
            continue
        body = r.text or ""
        attempts.append({"header": hname, "status": r.status_code,
                         "reflected": POISON_MARKER in body})
        if POISON_MARKER in body:
            findings.append({"header": hname, "status": r.status_code,
                             "preview": body[:300]})
    if findings:
        return ScanResult(
            capability="password_reset_scan", target=reset_url,
            verdict="VULNERABLE", severity="high",
            reason=(f"reset link reflects attacker-controlled host via "
                    f"{findings[0]['header']}"),
            evidence={"findings": findings, "attempts": attempts,
                      "reset_url": reset_url},
        )
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="password_reset_scan", target=reset_url,
            verdict="UNKNOWN", reason=unreached_reason(attempts),
            evidence={"attempts": attempts},
        )
    return ScanResult(
        capability="password_reset_scan", target=reset_url,
        verdict="PASS", severity="low",
        reason=f"no host reflection across {len(attempts)} headers",
        evidence={"attempts": attempts, "reset_url": reset_url},
    )
