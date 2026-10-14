from __future__ import annotations

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="cache_deception_scan",
    description=("Web cache deception: cacheable extensions on sensitive "
                 "endpoints trick a CDN into caching private responses."),
    category="access-control",
    cost="medium",
    destructive=False,
    idempotent=True,
)


_DEFAULT_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".jpeg", ".svg",
    ".ico", ".woff", ".woff2", ".txt", ".json", ".html",
]

_DEFAULT_CACHE_HEADERS = [
    "x-cache", "cf-cache-status", "x-cache-status",
    "x-served-by", "x-vercel-cache", "x-proxy-cache",
    "akamai-cache-status", "age",
]

_DEFAULT_HIT_MARKERS = ["hit", "cached"]


def _cfg():
    try:
        cfg = load_engine() or {}
        return cfg.get("cache_deception") or {}
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


def _get(url, headers, timeout, verify):
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(url, headers=headers or {})
        return {
            "status": r.status_code,
            "body": r.text or "",
            "headers": {k.lower(): v for k, v in r.headers.items()},
        }
    except _http.ConnectError as e:
        return {"status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _cache_state(headers, keys):
    return {k: headers.get(k, "") for k in keys if headers.get(k)}


def _is_cache_hit(cache_state, markers):
    if not cache_state:
        return False
    for k, v in cache_state.items():
        vl = str(v).lower()
        for m in markers:
            if m.lower() in vl:
                return True
    return False


def scan(target_url, headers=None, roe_guard=None, timeout=None):
    cfg = _cfg()
    if cfg.get("enabled") is False:
        return ScanResult(
            capability="cache_deception_scan", target=target_url,
            verdict="UNKNOWN", reason="cache_deception.enabled=false",
        )
    verify = _verify_tls()
    if timeout is None:
        timeout = float(cfg.get("timeout_seconds") or 8)
    extensions = cfg.get("extensions") or _DEFAULT_EXTENSIONS
    cache_keys = cfg.get("cache_header_keys") or _DEFAULT_CACHE_HEADERS
    hit_markers = cfg.get("cache_hit_markers") or _DEFAULT_HIT_MARKERS

    viol = _roe_block(roe_guard, target_url, "GET")
    if viol:
        return ScanResult(
            capability="cache_deception_scan", target=target_url,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )

    baseline = _get(target_url, headers, timeout, verify)
    if baseline.get("status") is None:
        return ScanResult(
            capability="cache_deception_scan", target=target_url,
            verdict="UNKNOWN",
            reason=f"baseline failed: {baseline.get('error')}",
        )
    if baseline["status"] != 200:
        return ScanResult(
            capability="cache_deception_scan", target=target_url,
            verdict="PASS", severity="low",
            reason=(f"baseline HTTP {baseline['status']}, not a sensitive "
                    f"200 to test cache deception against"),
        )

    base_body = baseline["body"]
    attempts = []
    findings = []

    for ext in extensions:
        url = target_url.rstrip("/") + ext
        viol = _roe_block(roe_guard, url, "GET")
        if viol:
            continue
        first = _get(url, headers, timeout, verify)
        if first.get("status") is None:
            attempts.append({"ext": ext, "error": first.get("error")})
            continue
        second = _get(url, headers, timeout, verify)
        cache_state = _cache_state(second.get("headers") or {}, cache_keys)
        same_body = (first.get("body") or "") == (second.get("body") or "")
        leaked_body = base_body and base_body in (second.get("body") or "")
        attempt = {
            "ext": ext,
            "url": url,
            "first_status": first.get("status"),
            "second_status": second.get("status"),
            "cache_headers": cache_state,
            "same_body": same_body,
            "leaked_body": leaked_body,
        }
        attempts.append(attempt)
        if (second.get("status") == 200
                and _is_cache_hit(cache_state, hit_markers)
                and (same_body or leaked_body)):
            findings.append(attempt)

    if findings:
        first = findings[0]
        return ScanResult(
            capability="cache_deception_scan", target=target_url,
            verdict="VULNERABLE", severity="high",
            reason=(f"cacheable extension {first['ext']} served a 200 with "
                    f"cache HIT on a sensitive endpoint"),
            evidence={
                "baseline_url": target_url,
                "findings": findings,
                "attempts": attempts,
            },
        )

    live = [a for a in attempts if a.get("second_status") is not None]
    if not live:
        return ScanResult(
            capability="cache_deception_scan", target=target_url,
            verdict="UNKNOWN", reason="all extension probes failed",
            evidence={"attempts": attempts},
        )
    return ScanResult(
        capability="cache_deception_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=(f"no cache deception signal across {len(live)} extensions"),
        evidence={"attempts": attempts},
    )


__all__ = ["scan", "CAPABILITY"]
