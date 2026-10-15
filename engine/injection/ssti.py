from __future__ import annotations

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .payloads import SSTI_PAYLOADS, COMMON_INJECTION_PARAMS
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


CAPABILITY = Capability(
    name="ssti_scan",
    description="Server-Side Template Injection detection across common params.",
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


def _send(url, method, params, json_body, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if json_body is not None:
                r = c.request(method, url, json=json_body,
                              headers=headers or {})
            else:
                r = c.request(method, url, params=params,
                              headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:8000]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def scan(target_url, param=None, method="GET", headers=None, roe_guard=None,
         timeout=8):
    verify = _verify_tls()
    params = [param] if param else COMMON_INJECTION_PARAMS[:8]

    attempts = []
    findings = []
    for pname in params:
        for payload, marker, engine in SSTI_PAYLOADS:
            if method.upper() == "POST":
                body = {pname: payload}
                r = _send(target_url, "POST", None, body, headers, timeout,
                          verify, roe_guard)
            else:
                r = _send(target_url, "GET", {pname: payload}, None, headers,
                          timeout, verify, roe_guard)
            if r.get("blocked"):
                return ScanResult(
                    capability="ssti_scan", target=target_url,
                    verdict="UNKNOWN", reason=r["error"],
                )
            body_text = r.get("body") or ""
            attempts.append({"param": pname, "engine": engine,
                             "status": r.get("status"), "error": r.get("error")})
            if marker and marker in body_text:
                findings.append({"param": pname, "engine": engine,
                                 "payload": payload, "marker": marker})
                break
        if findings:
            break

    if findings:
        return ScanResult(
            capability="ssti_scan", target=target_url,
            verdict="VULNERABLE", severity="high",
            reason=(f"SSTI confirmed on param '{findings[0]['param']}' "
                    f"({findings[0]['engine']})"),
            evidence={"findings": findings, "attempts": attempts[:30]},
        )
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="ssti_scan", target=target_url,
            verdict="UNKNOWN",
            reason=unreached_reason(attempts),
            evidence={"attempts": attempts[:30]},
        )
    return ScanResult(
        capability="ssti_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"no SSTI markers across {len(attempts)} attempts",
    )


__all__ = ["scan", "CAPABILITY"]
