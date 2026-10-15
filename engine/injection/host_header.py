from __future__ import annotations

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .payloads import HOST_HEADER_PAYLOADS, HOST_HEADER_NAMES
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


CAPABILITY = Capability(
    name="host_header_scan",
    description="Host header injection and reflection detection.",
    category="injection",
    cost="low",
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


def _baseline(target_url, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, target_url, "GET")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(target_url, headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:8000]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def scan(target_url, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()
    baseline = _baseline(target_url, headers, timeout, verify, roe_guard)
    if baseline.get("blocked"):
        return ScanResult(
            capability="host_header_scan", target=target_url,
            verdict="UNKNOWN", reason=baseline["error"],
        )

    attempts = []
    findings = []
    for hname in HOST_HEADER_NAMES:
        for payload in HOST_HEADER_PAYLOADS:
            viol = _roe_block(roe_guard, target_url, "GET")
            if viol:
                return ScanResult(
                    capability="host_header_scan", target=target_url,
                    verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
                )
            h = dict(headers or {})
            h[hname] = payload
            try:
                with _http.Client(timeout=timeout, verify=verify,
                                  follow_redirects=False) as c:
                    r = c.get(target_url, headers=h)
            except Exception as e:
                attempts.append({"header": hname, "payload": payload,
                                 "status": None, "error": str(e)})
                continue
            location = r.headers.get("Location", "")
            body = (r.text or "")[:8000]
            attempts.append({"header": hname, "payload": payload,
                             "status": r.status_code,
                             "location": location[:200]})
            if "attacker.example.com" in location:
                findings.append({"header": hname, "payload": payload,
                                 "type": "redirect",
                                 "location": location[:200]})
                break
            if "attacker.example.com" in body:
                findings.append({"header": hname, "payload": payload,
                                 "type": "reflection"})
                break
        if findings:
            break

    if findings:
        return ScanResult(
            capability="host_header_scan", target=target_url,
            verdict="VULNERABLE", severity="high",
            reason=(f"host header reflection via {findings[0]['header']} "
                    f"({findings[0]['type']})"),
            evidence={"findings": findings, "attempts": attempts[:30]},
        )
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="host_header_scan", target=target_url,
            verdict="UNKNOWN",
            reason=unreached_reason(attempts),
            evidence={"attempts": attempts[:30]},
        )
    return ScanResult(
        capability="host_header_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"no host header reflection across {len(attempts)} attempts",
    )


__all__ = ["scan", "CAPABILITY"]
