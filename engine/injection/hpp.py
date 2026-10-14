from __future__ import annotations

import hashlib
import secrets

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="hpp_scan",
    description=("HTTP Parameter Pollution: send single/double/comma/array "
                 "forms and detect last-wins reflection that could bypass "
                 "WAFs or authorization checks."),
    category="injection",
    cost="low",
    destructive=False,
    idempotent=True,
)


DEFAULT_PARAMS = [
    "id", "user_id", "role", "status", "amount", "price",
    "q", "search", "url", "redirect", "next", "return_url",
    "action", "type", "filter", "order", "sort",
]


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


def _request(url, params_list, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(url, params=params_list, headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:8000],
                "url": str(r.url)}
    except _http.ConnectError as e:
        return {"status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _body_hash(body):
    return hashlib.sha256((body or "").encode("utf-8", "ignore")).hexdigest()[:16]


def _probe_param(url, param, headers, timeout, verify, roe_guard):
    base_token = "SC_BASE_" + secrets.token_hex(4)
    over_token = "SC_OVER_" + secrets.token_hex(4)

    single = [(param, base_token)]
    double = [(param, base_token), (param, over_token)]
    comma = [(param, base_token + "," + over_token)]
    array = [(param + "[]", base_token), (param + "[]", over_token)]

    results = {}
    for label, params in (("single", single), ("double", double),
                          ("comma", comma), ("array", array)):
        r = _request(url, params, headers, timeout, verify, roe_guard)
        if r.get("blocked"):
            return {"blocked": True, "error": r["error"]}
        body = r.get("body") or ""
        results[label] = {
            "status": r.get("status"),
            "body_hash": _body_hash(body),
            "has_base": base_token in body,
            "has_over": over_token in body,
        }

    d = results["double"]
    if d["status"] is None:
        return None

    if d["has_over"] and not d["has_base"]:
        return {"param": param, "kind": "last_wins",
                "severity": "medium",
                "reason": (f"parameter '{param}' with duplicate values "
                           f"reflects only the second value — server uses "
                           f"last-wins; potential WAF/auth bypass"),
                "evidence": results}
    if d["has_base"] and d["has_over"]:
        return {"param": param, "kind": "array_parsing",
                "severity": "medium",
                "reason": (f"parameter '{param}' duplicate values both "
                           f"reflected — server may parse into array"),
                "evidence": results}
    if results["array"]["has_over"] and not results["array"]["has_base"]:
        return {"param": param, "kind": "array_last_wins",
                "severity": "medium",
                "reason": (f"array form of '{param}' reflects only second "
                           f"value"),
                "evidence": results}
    return {"param": param, "kind": None, "evidence": results}


def scan(target_url, params=None, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()
    viol = _roe_block(roe_guard, target_url, "GET")
    if viol:
        return ScanResult(
            capability="hpp_scan", target=target_url,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )
    param_list = params or DEFAULT_PARAMS[:10]
    findings = []
    attempts = 0
    for param in param_list:
        r = _probe_param(target_url, param, headers, timeout, verify, roe_guard)
        if r is None:
            continue
        if r.get("blocked"):
            return ScanResult(
                capability="hpp_scan", target=target_url,
                verdict="UNKNOWN", reason=r["error"],
            )
        attempts += 1
        if r.get("kind"):
            findings.append(r)
    if findings:
        return ScanResult(
            capability="hpp_scan", target=target_url,
            verdict="SUSPICIOUS", severity="medium",
            reason=(f"{len(findings)} parameter pollution signal(s): "
                    + ", ".join(f"{f['param']}:{f['kind']}" for f in findings[:5])),
            evidence={"findings": findings},
        )
    if attempts == 0:
        return ScanResult(
            capability="hpp_scan", target=target_url,
            verdict="UNKNOWN", reason="no parameters probed successfully",
        )
    return ScanResult(
        capability="hpp_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"no HPP reflection across {attempts} parameter(s)",
    )


__all__ = ["scan", "CAPABILITY", "DEFAULT_PARAMS"]
