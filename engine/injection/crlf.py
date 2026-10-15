from __future__ import annotations

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .payloads import CRLF_PAYLOADS, COMMON_INJECTION_PARAMS
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


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


def _augmented_crlf_payloads(target_url):
    try:
        from ..brains import payload_author
        extra = payload_author.propose_strings(
            "crlf_header_injection (each payload MUST inject a header named "
            "exactly 'X-Injected: payload' using CRLF / encoding variants)",
            {"target": target_url}, capability="crlf", cap=10)
    except Exception:
        extra = []
    tuples = [("llm_%d" % i, p) for i, p in enumerate(extra)
              if isinstance(p, str) and "X-Injected" in p]
    seen = set()
    out = []
    for t in tuples + list(CRLF_PAYLOADS):
        if t[1] not in seen:
            seen.add(t[1])
            out.append(t)
    return out


def scan(target_url, param=None, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()
    params = [param] if param else COMMON_INJECTION_PARAMS[:8]

    attempts = []
    findings = []
    crlf_payloads = _augmented_crlf_payloads(target_url)
    for pname in params:
        for label, payload in crlf_payloads:
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
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="crlf_scan", target=target_url,
            verdict="UNKNOWN",
            reason=unreached_reason(attempts),
            evidence={"attempts": attempts[:30]},
        )
    return ScanResult(
        capability="crlf_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"no CRLF injection across {len(attempts)} attempts",
    )


__all__ = ["scan", "CAPABILITY"]
