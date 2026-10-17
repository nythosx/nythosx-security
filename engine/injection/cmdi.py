from __future__ import annotations

import time

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


CAPABILITY = Capability(
    name="cmdi_scan",
    description="OS command injection via timing probes.",
    category="injection",
    cost="medium",
    destructive=False,
    idempotent=True,
)

TIMING_PAYLOADS = [
    ("linux_sleep", "; sleep {delay}", 5),
    ("linux_sleep_space", "&& sleep {delay} #", 5),
    ("linux_ping", "| ping -c {delay} 127.0.0.1", 5),
    ("win_timeout", "& timeout /t {delay} /nobreak", 5),
]

PARAMS = ["q", "cmd", "exec", "command", "ping", "host", "ip", "target",
          "url", "file", "name", "input", "query", "search", "searchTerm"]


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


def _send(url, param, payload, method, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}",
                "elapsed_ms": 0.0}
    t0 = time.perf_counter()
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if method.upper() == "POST":
                r = c.post(url, data={param: payload}, headers=headers or {})
            else:
                r = c.get(url, params={param: payload}, headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:2000],
                "elapsed_ms": (time.perf_counter() - t0) * 1000.0}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}",
                "elapsed_ms": (time.perf_counter() - t0) * 1000.0}


def scan(target_url, param=None, method="GET", headers=None, roe_guard=None,
         timeout=15, delay_seconds=5):
    verify = _verify_tls()
    params = [param] if param else PARAMS[:8]
    baseline = _send(target_url, params[0], "1", method, headers, timeout,
                     verify, roe_guard)
    if baseline.get("blocked"):
        return ScanResult(
            capability="cmdi_scan", target=target_url,
            verdict="UNKNOWN", reason=baseline["error"],
        )
    if baseline.get("error"):
        return ScanResult(
            capability="cmdi_scan", target=target_url,
            verdict="UNKNOWN", reason=baseline["error"],
        )
    base_ms = baseline.get("elapsed_ms", 0.0)
    threshold_ms = delay_seconds * 1000 * 0.6
    attempts = []
    findings = []
    for pname in params:
        for label, tmpl, delay in TIMING_PAYLOADS:
            payload = tmpl.format(delay=delay)
            r = _send(target_url, pname, payload, method, headers,
                      timeout + delay_seconds + 3, verify, roe_guard)
            if r.get("blocked"):
                return ScanResult(
                    capability="cmdi_scan", target=target_url,
                    verdict="UNKNOWN", reason=r["error"],
                )
            attempts.append({
                "param": pname, "payload": label,
                "status": r.get("status"),
                "elapsed_ms": round(r.get("elapsed_ms", 0), 1),
            })
            delta = r.get("elapsed_ms", 0) - base_ms
            if delta >= threshold_ms:
                findings.append({
                    "param": pname, "payload": label,
                    "delta_ms": round(delta, 1),
                    "baseline_ms": round(base_ms, 1),
                })
                break
        if findings:
            break
    if findings:
        return ScanResult(
            capability="cmdi_scan", target=target_url,
            verdict="VULNERABLE", severity="critical",
            reason=(f"OS command injection on param '{findings[0]['param']}' "
                    f"({findings[0]['payload']}, +{findings[0]['delta_ms']}ms)"),
            evidence={"findings": findings, "attempts": attempts[:30]},
        )
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="cmdi_scan", target=target_url,
            verdict="UNKNOWN", reason=unreached_reason(attempts),
            evidence={"attempts": attempts[:30]},
        )
    return ScanResult(
        capability="cmdi_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"no timing signal across {len(attempts)} attempts",
    )
