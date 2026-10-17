"""Tier-2 Phase 3 wiring: xss_t2 + sqli_t2 tools + oracles."""
from .chain_engine import register_tool
from .injection import xss_t2, sqli_t2
from . import oracle as _oracle


def _tool_xss_csp_bypass(orch, args):
    url = args.get("url") or orch.target
    csp = args.get("csp")
    if csp is None:
        try:
            from . import http as _http
            with _http.Client(timeout=8, follow_redirects=False) as c:
                r = c.get(url)
            csp = r.headers.get("Content-Security-Policy", "")
        except Exception as e:
            return {"verdict": "UNKNOWN",
                    "reason": "csp fetch failed: %s: %s"
                              % (type(e).__name__, e),
                    "evidence": {}}
    bypasses = xss_t2.enumerate_csp_bypasses(csp or "")
    if not csp:
        return {"verdict": "SUSPICIOUS",
                "reason": "no Content-Security-Policy header present",
                "evidence": {"csp": "", "bypasses": []}}
    if not bypasses:
        return {"verdict": "PASS",
                "reason": "CSP has no known bypass pattern",
                "evidence": {"csp": csp, "bypasses": []}}
    payloads = xss_t2.render_csp_bypass_payloads(bypasses)
    try:
        orch.add_fact("csp_bypass_found", True, source="xss_csp_bypass")
    except Exception:
        pass
    return {
        "verdict": "VULNERABLE",
        "reason": "CSP bypassable via %d class(es): %s"
                  % (len(bypasses),
                      ", ".join(b["class"] for b in bypasses)),
        "evidence": {"csp": csp, "bypasses": bypasses,
                      "payloads": payloads},
    }


def _tool_xss_mutation_bypass(orch, args):
    url = args.get("url") or orch.target
    param = args.get("param")
    if not param:
        return {"verdict": "UNKNOWN",
                "reason": "xss_mutation_bypass needs 'param'",
                "evidence": {}}
    bundle_text = args.get("bundle_text")
    sanitizer = xss_t2.detect_sanitizer(bundle_text or "")
    mutation_payloads = [p for _c, p in xss_t2.all_mutation_payloads()]
    # Reflection-only detection here; execution proof happens via
    # xss.scan with these payloads fed as budget.
    try:
        from . import xss as _xss
    except Exception:
        return {"verdict": "UNKNOWN",
                "reason": "xss module unavailable",
                "evidence": {}}
    reflected = []
    try:
        from . import http as _http
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        def _with_param(u, p, v):
            parsed = urlparse(u)
            q = parse_qs(parsed.query)
            q[p] = [v]
            return urlunparse(parsed._replace(
                query=urlencode(q, doseq=True)))
        with _http.Client(timeout=8, follow_redirects=False) as c:
            for label, payload in xss_t2.all_mutation_payloads():
                try:
                    r = c.get(_with_param(url, param, payload))
                except Exception:
                    continue
                if payload in (r.text or ""):
                    reflected.append({"class": label,
                                       "payload": payload[:120]})
    except Exception:
        pass
    if not reflected:
        return {"verdict": "PASS",
                "reason": "no mutation payload reflected (may still need "
                          "Playwright execution proof if reflection is "
                          "encoded)",
                "evidence": {"sanitizer": sanitizer,
                              "payloads_tried": len(mutation_payloads)}}
    return {
        "verdict": "SUSPICIOUS",
        "reason": ("%d mutation payload(s) reflected; needs Playwright "
                    "execution proof" % len(reflected)),
        "evidence": {"sanitizer": sanitizer, "reflected": reflected},
    }


def _tool_sqli_second_order(orch, args):
    store_url = args.get("store_url")
    reader_urls = args.get("reader_endpoints")
    if isinstance(reader_urls, str):
        reader_urls = [u.strip() for u in reader_urls.split(",")
                        if u.strip()]
    if not store_url or not reader_urls:
        return {"verdict": "UNKNOWN",
                "reason": "sqli_second_order needs store_url and "
                          "reader_endpoints",
                "evidence": {}}
    try:
        r = sqli_t2.probe_second_order(
            store_url,
            store_method=args.get("store_method", "POST"),
            store_param=args.get("store_param", "bio"),
            payload=args.get("payload") or "admin'-- -",
            reader_endpoints=reader_urls,
            reader_method=args.get("reader_method", "GET"),
            reader_param=args.get("reader_param", "q"),
            reader_value=args.get("reader_value", "1"),
            roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "second_order failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    if r.get("second_order_confirmed"):
        try:
            orch.add_fact("second_order_sqli_confirmed", True,
                          source="sqli_second_order")
        except Exception:
            pass
    return {"verdict": r.get("verdict", "UNKNOWN"),
            "reason": r.get("reason", ""),
            "evidence": r.get("evidence", {})}


def _tool_sqli_chunked_hpp(orch, args):
    url = args.get("url") or orch.target
    param = args.get("param") or "id"
    method = (args.get("method") or "GET").upper()
    try:
        r = sqli_t2.probe_chunked_query(
            url, param=param, method=method,
            roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "chunked_hpp failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    return {"verdict": r.get("verdict", "UNKNOWN"),
            "reason": r.get("reason", ""),
            "evidence": r.get("evidence", {})}


def _tool_sqli_json_context(orch, args):
    url = args.get("url") or orch.target
    method = (args.get("method") or "POST").upper()
    try:
        r = sqli_t2.probe_json_context(
            url, method=method,
            roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "json_context failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    return {"verdict": r.get("verdict", "UNKNOWN"),
            "reason": r.get("reason", ""),
            "evidence": r.get("evidence", {})}


def _tool_sqli_boolean_timing(orch, args):
    url = args.get("url") or orch.target
    param = args.get("param") or "id"
    method = (args.get("method") or "GET").upper()
    try:
        r = sqli_t2.probe_boolean_timing(
            url, param=param, method=method,
            roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "boolean_timing failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    return {"verdict": r.get("verdict", "UNKNOWN"),
            "reason": r.get("reason", ""),
            "evidence": r.get("evidence", {})}


def _tool_sqli_error_based(orch, args):
    url = args.get("url") or orch.target
    param = args.get("param") or "id"
    method = (args.get("method") or "GET").upper()
    dbms = args.get("dbms") or orch.get_fact("dbms") or None
    try:
        r = sqli_t2.probe_error_based(
            url, param=param, method=method, dbms=dbms,
            roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "error_based failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    if r.get("verdict") == "VULNERABLE":
        try:
            orch.add_fact("error_channel_disclosure", True,
                          source="sqli_error_based")
        except Exception:
            pass
    return {"verdict": r.get("verdict", "UNKNOWN"),
            "reason": r.get("reason", ""),
            "evidence": r.get("evidence", {})}


register_tool("xss_csp_bypass", _tool_xss_csp_bypass,
              provides=["csp_bypass_found"])
register_tool("xss_mutation_bypass", _tool_xss_mutation_bypass)
register_tool("sqli_second_order", _tool_sqli_second_order,
              provides=["second_order_sqli_confirmed"])
register_tool("sqli_chunked_hpp", _tool_sqli_chunked_hpp)
register_tool("sqli_json_context", _tool_sqli_json_context)
register_tool("sqli_boolean_timing", _tool_sqli_boolean_timing)
register_tool("sqli_error_based", _tool_sqli_error_based,
              provides=["error_channel_disclosure"])


def _oracle_csp_bypass_found(oracle, context):
    for s in (context.get("steps") or []):
        body = s.get("body") or ""
        if "CSP bypassable" in body or "csp_bypass_found" in body:
            return {"verdict": oracle.get("verdict", "VULNERABLE"),
                    "reason": "CSP enumerated as bypassable",
                    "evidence": {"preview": body[:400]}}
    return {"verdict": "PASS",
            "reason": "no CSP bypass in context", "evidence": {}}


def _oracle_second_order_confirmed(oracle, context):
    for s in (context.get("steps") or []):
        body = s.get("body") or ""
        if "second_order_confirmed" in body and "true" in body.lower():
            return {"verdict": oracle.get("verdict", "VULNERABLE"),
                    "reason": "stored payload changed reader behavior",
                    "evidence": {"preview": body[:400]}}
    return {"verdict": "PASS",
            "reason": "no second-order confirmation in context",
            "evidence": {}}


def _oracle_error_channel_disclosure(oracle, context):
    for s in (context.get("steps") or []):
        body = s.get("body") or ""
        if "error-based channel leaked data" in body:
            return {"verdict": oracle.get("verdict", "VULNERABLE"),
                    "reason": "error channel leaked data",
                    "evidence": {"preview": body[:400]}}
    return {"verdict": "PASS",
            "reason": "no error-channel disclosure in context",
            "evidence": {}}


_oracle._HANDLERS.update({
    "csp_bypass_found": _oracle_csp_bypass_found,
    "second_order_confirmed": _oracle_second_order_confirmed,
    "error_channel_disclosure": _oracle_error_channel_disclosure,
})
