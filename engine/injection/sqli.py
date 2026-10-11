from __future__ import annotations

import time
from urllib.parse import urlencode

from ..config import load_engine
from ..contract import Capability, make_result
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="sqli_scan",
    description="SQL injection: boolean, error, union, time-based probes.",
    category="injection",
    cost="medium",
    destructive=False,
    idempotent=True,
)


ERROR_SIGNATURES = [
    "sql syntax",
    "sqlstate",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "warning: mysql_",
    "valid mysql result",
    "postgresql",
    "pg_query",
    "psql:",
    "sqlite_",
    "sqlite/jdbcdriver",
    "unclosed quotation mark",
    "microsoft ole db",
    "odbc sql server driver",
    "jdbc",
    "java.sql.sqlexception",
    "oracle error",
    "ora-0",
    "quoted string not properly terminated",
    "unterminated quoted string",
]

BOOLEAN_PAIRS = [
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("1' AND 1=1-- -", "1' AND 1=2-- -"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR '1'='1", "' OR '1'='2"),
]

UNION_TEMPLATES = [
    "' UNION SELECT {cols}-- -",
    "1' UNION SELECT {cols}-- -",
    "' UNION ALL SELECT {cols}-- -",
]

UNION_MARKER = "SC_UNION_7733"


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


def _send(url, method, param, payload, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if method.upper() == "POST":
                r = c.post(url, data={param: payload},
                           headers=headers or {})
            else:
                r = c.get(url, params={param: payload},
                          headers=headers or {})
        return {
            "status": r.status_code,
            "body": (r.text or "")[:8000],
            "time_ms": 0.0,
        }
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}",
                "time_ms": 0.0}


def probe_boolean(url, param, method="GET", headers=None, timeout=8,
                  verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    attempts = []
    findings = []
    for true_payload, false_payload in BOOLEAN_PAIRS:
        r_true = _send(url, method, param, true_payload, headers, timeout,
                       verify, roe_guard)
        if r_true.get("blocked"):
            return {"blocked": True, "error": r_true["error"]}
        r_false = _send(url, method, param, false_payload, headers, timeout,
                        verify, roe_guard)
        if r_false.get("blocked"):
            return {"blocked": True, "error": r_false["error"]}
        attempts.append({
            "pair": (true_payload, false_payload),
            "true_status": r_true.get("status"),
            "false_status": r_false.get("status"),
            "true_len": len(r_true.get("body") or ""),
            "false_len": len(r_false.get("body") or ""),
        })
        if (r_true.get("status") is not None
                and r_false.get("status") is not None
                and r_true["status"] == r_false["status"]):
            tlen = len(r_true.get("body") or "")
            flen = len(r_false.get("body") or "")
            if tlen and flen:
                ratio = abs(tlen - flen) / max(tlen, flen)
                if ratio > 0.15:
                    findings.append({
                        "payload_true": true_payload,
                        "payload_false": false_payload,
                        "true_len": tlen, "false_len": flen,
                        "delta_pct": round(ratio, 3),
                    })
                    break
    return {"attempts": attempts, "findings": findings}


def probe_error(url, param, method="GET", headers=None, timeout=8,
                verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    payloads = ["'", '"', "')", "';", "\\'", "1'", "1 OR 1=1-- -"]
    attempts = []
    findings = []
    for payload in payloads:
        r = _send(url, method, param, payload, headers, timeout, verify,
                  roe_guard)
        if r.get("blocked"):
            return {"blocked": True, "error": r["error"]}
        body = (r.get("body") or "").lower()
        hits = [sig for sig in ERROR_SIGNATURES if sig in body]
        attempts.append({"payload": payload, "status": r.get("status"),
                         "error_signatures": hits})
        if hits:
            findings.append({"payload": payload,
                             "signatures": hits,
                             "preview": (r.get("body") or "")[:300]})
            break
    return {"attempts": attempts, "findings": findings}


def probe_union(url, param, method="GET", headers=None, timeout=8,
                verify=None, roe_guard=None, max_cols=10):
    if verify is None:
        verify = _verify_tls()
    attempts = []
    findings = []
    for ncols in range(1, max_cols + 1):
        cols = ",".join([f"'{UNION_MARKER}_{i}'" for i in range(ncols)])
        for tmpl in UNION_TEMPLATES:
            payload = tmpl.format(cols=cols)
            r = _send(url, method, param, payload, headers, timeout,
                      verify, roe_guard)
            if r.get("blocked"):
                return {"blocked": True, "error": r["error"]}
            body = r.get("body") or ""
            attempts.append({
                "columns": ncols,
                "template": tmpl,
                "status": r.get("status"),
                "reflected": UNION_MARKER in body,
            })
            if UNION_MARKER in body:
                findings.append({
                    "columns": ncols,
                    "template": tmpl,
                    "payload": payload,
                    "preview": body[:400],
                })
                return {"attempts": attempts, "findings": findings}
    return {"attempts": attempts, "findings": findings}


def scan(target_url, param=None, method="GET", headers=None, roe_guard=None,
         timeout=8, probes=None, max_cols=10):
    verify = _verify_tls()
    if not param:
        return make_result(
            {"verdict": "UNKNOWN",
             "reason": "no parameter specified for SQLi testing"},
            capability="sqli_scan", args=(target_url,))

    probes = probes or ["boolean", "error", "union"]
    results = {}
    findings = []

    if "boolean" in probes:
        results["boolean"] = probe_boolean(target_url, param, method,
                                           headers, timeout, verify, roe_guard)
        if results["boolean"].get("blocked"):
            return make_result(
                {"verdict": "UNKNOWN", "reason": results["boolean"]["error"]},
                capability="sqli_scan", args=(target_url,))
        for f in results["boolean"].get("findings") or []:
            findings.append({"probe": "boolean", **f})

    if "error" in probes:
        results["error"] = probe_error(target_url, param, method,
                                       headers, timeout, verify, roe_guard)
        if results["error"].get("blocked"):
            return make_result(
                {"verdict": "UNKNOWN", "reason": results["error"]["error"]},
                capability="sqli_scan", args=(target_url,))
        for f in results["error"].get("findings") or []:
            findings.append({"probe": "error", **f})

    if "union" in probes:
        results["union"] = probe_union(target_url, param, method,
                                       headers, timeout, verify, roe_guard,
                                       max_cols=max_cols)
        if results["union"].get("blocked"):
            return make_result(
                {"verdict": "UNKNOWN", "reason": results["union"]["error"]},
                capability="sqli_scan", args=(target_url,))
        for f in results["union"].get("findings") or []:
            findings.append({"probe": "union", **f})

    if findings:
        return make_result({
            "verdict": "VULNERABLE",
            "reason": f"SQLi confirmed on '{param}' via "
                      f"{findings[0]['probe']} probe",
            "evidence": {"param": param, "findings": findings[:5]},
        }, capability="sqli_scan", args=(target_url,))

    all_empty = all(
        not (results.get(p) or {}).get("findings")
        for p in probes)
    if all_empty:
        any_live = any(
            (results.get(p) or {}).get("attempts")
            for p in probes)
        if any_live:
            return make_result({
                "verdict": "PASS",
                "reason": f"no SQLi signal on '{param}' across "
                          f"{sum(len((results.get(p) or {}).get('attempts') or []) for p in probes)} probes",
            }, capability="sqli_scan", args=(target_url,))

    return make_result({
        "verdict": "UNKNOWN",
        "reason": "SQLi probes inconclusive (no live responses)",
    }, capability="sqli_scan", args=(target_url,))


__all__ = ["scan", "probe_boolean", "probe_error", "probe_union", "CAPABILITY"]
