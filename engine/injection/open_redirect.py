from __future__ import annotations

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .payloads import OPEN_REDIRECT_PAYLOADS
from .. import http as _http


CAPABILITY = Capability(
    name="open_redirect_scan",
    description="Open redirect detection via Location header analysis.",
    category="injection",
    cost="low",
    destructive=False,
    idempotent=True,
)


REDIRECT_PARAMS = ["url", "next", "redirect", "redirect_uri", "return",
                    "return_to", "return_url", "returnUrl", "continue",
                    "dest", "destination", "r", "u", "target", "link",
                    "to", "goto", "out", "view"]


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


def _payload_matches_location(payload, location):
    if not location:
        return False
    loc = location.lower()
    if "attacker.example.com" not in loc:
        return False
    return True


def scan(target_url, param=None, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()
    params = [param] if param else REDIRECT_PARAMS

    attempts = []
    findings = []
    for pname in params:
        for payload in OPEN_REDIRECT_PAYLOADS:
            viol = _roe_block(roe_guard, target_url, "GET")
            if viol:
                return ScanResult(
                    capability="open_redirect_scan", target=target_url,
                    verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
                )
            try:
                with _http.Client(timeout=timeout, verify=verify,
                                  follow_redirects=False) as c:
                    r = c.get(target_url, params={pname: payload},
                              headers=headers or {})
            except Exception as e:
                attempts.append({"param": pname, "payload": payload,
                                 "status": None, "error": str(e)})
                continue
            location = r.headers.get("Location", "")
            attempts.append({"param": pname, "payload": payload,
                             "status": r.status_code,
                             "location": location[:200]})
            if (300 <= r.status_code < 400
                    and _payload_matches_location(payload, location)):
                findings.append({"param": pname, "payload": payload,
                                 "location": location[:200]})
                break
        if findings:
            break

    if findings:
        return ScanResult(
            capability="open_redirect_scan", target=target_url,
            verdict="VULNERABLE", severity="medium",
            reason=(f"open redirect on param '{findings[0]['param']}' "
                    f"→ {findings[0]['location'][:80]}"),
            evidence={"findings": findings, "attempts": attempts[:30]},
        )
    if not attempts:
        return ScanResult(
            capability="open_redirect_scan", target=target_url,
            verdict="UNKNOWN", reason="no attempts made",
        )
    return ScanResult(
        capability="open_redirect_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"no open redirect across {len(attempts)} attempts",
    )


__all__ = ["scan", "CAPABILITY"]
