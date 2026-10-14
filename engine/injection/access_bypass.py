from __future__ import annotations

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="access_bypass_scan",
    description="403/401 bypass via header overrides and path mutations.",
    category="access-control",
    cost="low",
    destructive=False,
    idempotent=True,
)


_DEFAULT_HEADER_OVERRIDES = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "X-Forwarded-Prefix",
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Client-IP",
    "X-Trusted-By",
]

_DEFAULT_PATH_MUTATIONS = [
    "{p}/",
    "{p}/.",
    "{p}/%2e",
    "{p}%20",
    "{p}%09",
    "{p}?x=1",
    "{p}..;/",
    "{p}#",
    "{p}%23",
    "{p}/*",
    "{p}.json",
    "{p}.html",
]

_INTERNAL_IPS = {
    "127.0.0.1", "localhost", "::1", "0.0.0.0",
}


def _cfg():
    try:
        cfg = load_engine() or {}
        return cfg.get("access_bypass") or {}
    except Exception:
        return {}


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


def _baseline(url, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(url, headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:500]}
    except _http.ConnectError as e:
        return {"status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _header_value(name, path):
    if name in ("X-HTTP-Method-Override", "X-Method-Override"):
        return "GET"
    if name in ("X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
                "X-Remote-IP", "X-Client-IP"):
        return "127.0.0.1"
    if name == "X-Forwarded-Host":
        return "localhost"
    return path or "/"


def _is_bypass(baseline_status, status, body):
    if status is None:
        return False
    if baseline_status in (401, 403) and status in (200, 201, 202, 204):
        return True
    return False


def scan(target_url, headers=None, roe_guard=None, timeout=None, param=None):
    cfg = _cfg()
    if cfg.get("enabled") is False:
        return ScanResult(
            capability="access_bypass_scan", target=target_url,
            verdict="UNKNOWN", reason="access_bypass.enabled=false",
        )
    verify = _verify_tls()
    if timeout is None:
        timeout = float(cfg.get("timeout_seconds") or 8)
    header_overrides = cfg.get("header_overrides") or _DEFAULT_HEADER_OVERRIDES
    path_mutations = cfg.get("path_mutations") or _DEFAULT_PATH_MUTATIONS

    base = _baseline(target_url, headers, timeout, verify, roe_guard)
    if base.get("blocked"):
        return ScanResult(
            capability="access_bypass_scan", target=target_url,
            verdict="UNKNOWN", reason=base["error"],
        )
    base_status = base.get("status")
    if base_status not in (401, 403):
        return ScanResult(
            capability="access_bypass_scan", target=target_url,
            verdict="PASS", severity="low",
            reason=f"baseline HTTP {base_status}, not an access-control gate",
        )

    from urllib.parse import urlparse
    parts = urlparse(target_url)
    path = parts.path or "/"

    findings = []
    attempts = []

    for hname in header_overrides:
        h = dict(headers or {})
        h[hname] = _header_value(hname, path)
        viol = _roe_block(roe_guard, target_url, "GET")
        if viol:
            return ScanResult(
                capability="access_bypass_scan", target=target_url,
                verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
            )
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.get(target_url, headers=h)
        except Exception as e:
            attempts.append({"header": hname, "error": str(e)[:120]})
            continue
        attempts.append({"header": hname, "status": r.status_code})
        if _is_bypass(base_status, r.status_code, r.text or ""):
            findings.append({
                "type": "header", "header": hname,
                "value": h[hname], "status": r.status_code,
                "preview": (r.text or "")[:200],
            })

    for tmpl in path_mutations:
        mut_path = tmpl.replace("{p}", path)
        mut_url = f"{parts.scheme}://{parts.netloc}{mut_path}"
        viol = _roe_block(roe_guard, mut_url, "GET")
        if viol:
            continue
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.get(mut_url, headers=headers or {})
        except Exception as e:
            attempts.append({"path": mut_path, "error": str(e)[:120]})
            continue
        attempts.append({"path": mut_path, "status": r.status_code})
        if _is_bypass(base_status, r.status_code, r.text or ""):
            findings.append({
                "type": "path", "path": mut_path,
                "status": r.status_code,
                "preview": (r.text or "")[:200],
            })

    if findings:
        first = findings[0]
        label = first.get("header") or first.get("path")
        return ScanResult(
            capability="access_bypass_scan", target=target_url,
            verdict="VULNERABLE", severity="high",
            reason=(f"HTTP {base_status} gate bypassed via {first['type']} "
                    f"({label})"),
            evidence={
                "baseline_status": base_status,
                "findings": findings,
                "attempts": attempts,
            },
        )

    live = [a for a in attempts if a.get("status") is not None]
    if not live:
        from ..util import summarize_failures
        why = summarize_failures(attempts)
        return ScanResult(
            capability="access_bypass_scan", target=target_url,
            verdict="UNKNOWN",
            reason=(f"all requests failed ({why})" if why
                    else "all requests failed"),
            evidence={"attempts": attempts},
        )

    return ScanResult(
        capability="access_bypass_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=(f"no bypass across {len(live)} attempts on a HTTP "
                f"{base_status} gate"),
        evidence={"attempts": attempts},
    )


__all__ = ["scan", "CAPABILITY"]
