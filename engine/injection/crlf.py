from __future__ import annotations

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .payloads import CRLF_PAYLOADS, COMMON_INJECTION_PARAMS
from .. import http as _http


CAPABILITY = Capability(
    name="crlf_scan",
    description="CRLF injection / HTTP response header splitting.",
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


def scan(target_url, param=None, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()
    params = [param] if param else COMMON_INJECTION_PARAMS[:8]

    attempts = []
    findings = []
    for pname in params:
        for label, payload in CRLF_PAYLOADS:
            viol = _roe_block(roe_guard, target_url, "GET")
            if viol:
                return ScanResult(
                    capability="crlf_scan", target=target_url,
                    verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
                )
            try:
                with _http.Client(timeout=timeout, verify=verify,
                                  follow_redirects=False) as c:
                    r = c.get(target_url,
                              params={pname: payload},
                              headers=headers or {})
            except Exception as e:
                attempts.append({"param": pname, "payload": label,
                                 "status": None, "error": str(e)})
                continue
            attempts.append({"param": pname, "payload": label,
                             "status": r.status_code})
            header_names = {k.lower() for k in r.headers.keys()}
            if "x-injected" in header_names:
                findings.append({"param": pname, "payload": label,
                                 "injected_header": r.headers.get("X-Injected")})
                break
        if findings:
            break

    if findings:
        return ScanResult(
            capability="crlf_scan", target=target_url,
            verdict="VULNERABLE", severity="high",
            reason=(f"CRLF injection on param '{findings[0]['param']}' — "
                    f"injected header observed"),
            evidence={"findings": findings, "attempts": attempts[:30]},
        )
    statuses = [a["status"] for a in attempts if a["status"] is not None]
    if not statuses:
        from ..util import summarize_failures
        why = summarize_failures(attempts)
        return ScanResult(
            capability="crlf_scan", target=target_url,
            verdict="UNKNOWN",
            reason=f"all requests failed ({why})" if why else "all requests failed",
            evidence={"attempts": attempts[:30]},
        )
    return ScanResult(
        capability="crlf_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"no CRLF injection across {len(attempts)} attempts",
    )


__all__ = ["scan", "CAPABILITY"]
