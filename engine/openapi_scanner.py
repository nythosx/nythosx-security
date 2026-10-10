import json
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


SPEC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/api/docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/docs/openapi.json",
    "/docs/swagger.json",
    "/.well-known/schema-discovery",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v1/swagger.json",
]

SWAGGER_UI_PATHS = [
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger/",
    "/api/docs/",
    "/docs/",
    "/redoc",
]


STRING_PAYLOADS = [
    "",
    "A" * 10000,
    "'",
    '"',
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "${7*7}",
    "{{7*7}}",
    "\x00",
    "\r\nInjected-Header: x",
    "%00",
    "file:///etc/passwd",
]

NUMBER_PAYLOADS = [
    0,
    -1,
    -2147483648,
    2147483647,
    2147483648,
    -9223372036854775808,
    9223372036854775807,
    0.1,
    1.5,
    -0.1,
    1e308,
    -1e308,
    float("inf"),
    float("nan"),
]

BOOL_PAYLOADS = [True, False, "true", "false", 0, 1, "yes", "no", "", None]

AUTH_TYPE_MAP = {
    "http": "HTTP",
    "apiKey": "API Key",
    "oauth2": "OAuth2",
    "openIdConnect": "OpenID Connect",
    "basic": "Basic",
    "bearer": "Bearer",
}

INSECURE_SCHEMES = {"http", "httpbasic"}


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


def _fetch(url, timeout=10, verify=None, roe_guard=None, headers=None):
    if verify is None:
        verify = _verify_tls()
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return {"url": url, "blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with httpx.Client(timeout=timeout, verify=verify,
                          follow_redirects=True) as c:
            r = c.get(url, headers=headers or {})
        return {"url": str(r.url), "status": r.status_code,
                "body": r.text or "", "headers": dict(r.headers)}
    except httpx.ConnectError as e:
        return {"url": url, "status": None,
                "error": f"connection error: {e}"}
    except httpx.TimeoutException:
        return {"url": url, "status": None, "error": "timeout"}
    except Exception as e:
        return {"url": url, "status": None,
                "error": f"{type(e).__name__}: {e}"}


def _try_parse_spec(text):
    if not text:
        return None
    text = text.strip()
    if not text or (not text.startswith("{") and not text.startswith("[")):
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if "openapi" in data or "swagger" in data:
        if "paths" in data or "components" in data or "definitions" in data:
            return data
    return None


def _try_parse_spec_yaml(text):
    if not HAS_YAML or not text:
        return None
    try:
        data = yaml.safe_load(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if "openapi" in data or "swagger" in data:
        if "paths" in data or "components" in data or "definitions" in data:
            return data
    return None


def _extract_embedded_spec(html):
    if not html or "swagger-ui" not in html.lower() and "openapi" not in html.lower():
        return None
    patterns = [
        r'url:\s*["\']([^"\']+\.(?:json|yaml|yml))["\']',
        r'spec-url\s*=\s*["\']([^"\']+)["\']',
        r'data-url\s*=\s*["\']([^"\']+)["\']',
        r'["\']([^"\']*openapi\.(?:json|yaml|yml))["\']',
        r'["\']([^"\']*swagger\.(?:json|yaml|yml))["\']',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def discover_spec(base_url, timeout=10, verify=None, roe_guard=None, headers=None):
    if verify is None:
        verify = _verify_tls()
    base = base_url.rstrip("/")
    parsed_base = urlparse(base)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    candidates = []
    for path in SPEC_PATHS:
        candidates.append(origin + path)
        if base != origin:
            candidates.append(base + path)

    for url in candidates:
        r = _fetch(url, timeout=timeout, verify=verify, roe_guard=roe_guard,
                   headers=headers)
        if r.get("blocked"):
            return {"error": r["error"]}
        if r.get("status") != 200:
            continue
        spec = _try_parse_spec(r["body"]) or _try_parse_spec_yaml(r["body"])
        if spec:
            version = spec.get("openapi") or spec.get("swagger") or "unknown"
            return {"url": url, "spec": spec, "version": str(version),
                    "format": "openapi" if "openapi" in spec else "swagger",
                    "origin": origin}

    for path in SWAGGER_UI_PATHS:
        url = origin + path
        r = _fetch(url, timeout=timeout, verify=verify, roe_guard=roe_guard,
                   headers=headers)
        if r.get("blocked"):
            return {"error": r["error"]}
        if r.get("status") != 200:
            continue
        body = r.get("body") or ""
        embedded = _extract_embedded_spec(body)
        if not embedded:
            continue
        if embedded.startswith(("http://", "https://")):
            spec_url = embedded
        else:
            spec_url = urljoin(r["url"], embedded)
        sr = _fetch(spec_url, timeout=timeout, verify=verify,
                    roe_guard=roe_guard, headers=headers)
        if sr.get("blocked"):
            return {"error": sr["error"]}
        if sr.get("status") == 200:
            spec = _try_parse_spec(sr["body"]) or _try_parse_spec_yaml(sr["body"])
            if spec:
                version = spec.get("openapi") or spec.get("swagger") or "unknown"
                return {"url": spec_url, "spec": spec, "version": str(version),
                        "format": "openapi" if "openapi" in spec else "swagger",
                        "origin": origin, "discovered_via": url}
    return None


def extract_endpoints(spec, origin):
    paths = spec.get("paths") or {}
    base_path = ""
    if "servers" in spec and spec["servers"]:
        srv = spec["servers"][0]
        base_path = urlparse(srv.get("url", "")).path or ""
    elif "basePath" in spec:
        base_path = spec["basePath"] or ""
    endpoints = []
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            op = ops.get(method)
            if not isinstance(op, dict):
                continue
            url = origin + (base_path or "") + path
            endpoints.append({
                "path": path,
                "method": method.upper(),
                "operation_id": op.get("operationId", ""),
                "summary": op.get("summary", ""),
                "parameters": _normalize_params(op.get("parameters") or []),
                "request_body": _normalize_body(op.get("requestBody")),
                "security": op.get("security", spec.get("security") or []),
                "responses": list((op.get("responses") or {}).keys()),
                "tags": op.get("tags") or [],
                "url": url,
            })
    return endpoints


def _normalize_params(params):
    out = []
    for p in params:
        if not isinstance(p, dict):
            continue
        out.append({
            "name": p.get("name", ""),
            "in": p.get("in", ""),
            "required": bool(p.get("required")),
            "schema": p.get("schema") or p.get("type") or {},
            "example": p.get("example"),
        })
    return out


def _normalize_body(body):
    if not body:
        return None
    if not isinstance(body, dict):
        return None
    content = body.get("content") or {}
    out = {"required": bool(body.get("required")), "content": {}}
    for ct, ctype in content.items():
        if not isinstance(ctype, dict):
            continue
        out["content"][ct] = {"schema": ctype.get("schema") or {}}
    return out


def extract_auth_schemes(spec):
    schemes = {}
    if "components" in spec:
        schemes = spec["components"].get("securitySchemes") or {}
    elif "securityDefinitions" in spec:
        schemes = spec["securityDefinitions"] or {}
    result = []
    for name, s in schemes.items():
        if not isinstance(s, dict):
            continue
        stype = s.get("type", "unknown")
        entry = {"name": name, "type": stype,
                 "scheme": s.get("scheme", ""),
                 "in": s.get("in", ""),
                 "header_name": s.get("name", ""),
                 "bearerFormat": s.get("bearerFormat", ""),
                 "flows": list((s.get("flows") or {}).keys()),
                 "openIdConnectUrl": s.get("openIdConnectUrl", ""),
                 "description": s.get("description", "")}
        result.append(entry)
    return result


def _make_fuzz_values(schema):
    values = []
    if not isinstance(schema, dict):
        return [{"type": "string", "value": "test"}]
    stype = schema.get("type", "string")
    if isinstance(stype, list):
        stype = stype[0] if stype else "string"
    enum = schema.get("enum")
    if enum:
        for v in enum[:3]:
            values.append({"type": "enum", "value": v})
        values.append({"type": "enum_invalid",
                       "value": "NOT_IN_ENUM_" + str(int(time.time()))[-6:]})
        return values

    if stype == "integer" or stype == "number":
        mn = schema.get("minimum")
        mx = schema.get("maximum")
        if isinstance(mn, (int, float)):
            values.append({"type": "boundary_min", "value": mn})
            values.append({"type": "below_min", "value": mn - 1})
        if isinstance(mx, (int, float)):
            values.append({"type": "boundary_max", "value": mx})
            values.append({"type": "above_max", "value": mx + 1})
        for v in (0, -1, 2147483647, 2147483648, -2147483648,
                  9223372036854775807, -9223372036854775808):
            values.append({"type": "boundary", "value": v})
        values.append({"type": "type_confusion", "value": "not_a_number"})
        return values

    if stype == "boolean":
        for v in (True, False, "true", "false", 0, 1, "", None, "yes"):
            values.append({"type": "bool_variant", "value": v})
        return values

    if stype == "array":
        values.append({"type": "empty_array", "value": []})
        values.append({"type": "one_null", "value": [None]})
        values.append({"type": "many_nulls", "value": [None] * 50})
        values.append({"type": "type_confusion", "value": "not_an_array"})
        return values

    if stype == "object":
        values.append({"type": "empty_object", "value": {}})
        values.append({"type": "type_confusion", "value": "not_an_object"})
        return values

    maxlen = schema.get("maxLength")
    minlen = schema.get("minLength")
    pat = schema.get("pattern")
    if isinstance(minlen, int) and minlen > 0:
        values.append({"type": "below_minlen", "value": "A" * max(0, minlen - 1)})
        values.append({"type": "at_minlen", "value": "A" * minlen})
    if isinstance(maxlen, int):
        values.append({"type": "at_maxlen", "value": "A" * maxlen})
        values.append({"type": "above_maxlen", "value": "A" * (maxlen + 1)})
    if pat:
        values.append({"type": "pattern_violation", "value": "!@#$%^&*()"})
    for payload in STRING_PAYLOADS[:12]:
        values.append({"type": "injection", "value": payload})
    return values


def _substitute_path(path, params):
    result = path
    for p in params:
        if p.get("in") == "path":
            sample = _sample_from_schema(p.get("schema") or {})
            result = result.replace("{" + p["name"] + "}", str(sample))
    return result


def _sample_from_schema(schema):
    stype = (schema or {}).get("type", "string")
    if stype == "integer":
        return 1
    if stype == "number":
        return 1.0
    if stype == "boolean":
        return True
    if stype == "array":
        return []
    return "1"


def fuzz_endpoint(endpoint, origin, timeout=8, verify=None, roe_guard=None,
                  headers=None, max_cases=40):
    if verify is None:
        verify = _verify_tls()
    out = {"endpoint": f"{endpoint['method']} {endpoint['path']}",
           "url": endpoint["url"],
           "cases": [], "anomalies": []}
    cases = []
    query_params = [p for p in endpoint["parameters"]
                    if p.get("in") == "query"]
    header_params = [p for p in endpoint["parameters"]
                     if p.get("in") == "header"]
    path_params = [p for p in endpoint["parameters"]
                   if p.get("in") == "path"]

    for p in query_params[:3]:
        schema = p.get("schema") or {}
        for v in _make_fuzz_values(schema)[:8]:
            cases.append({"kind": "query", "param": p["name"],
                          "value_type": v["type"], "value": v["value"]})

    for p in header_params[:3]:
        schema = p.get("schema") or {}
        for v in _make_fuzz_values(schema)[:6]:
            cases.append({"kind": "header", "param": p["name"],
                          "value_type": v["type"], "value": v["value"]})

    if endpoint.get("request_body"):
        for ct, ctype in (endpoint["request_body"].get("content") or {}).items():
            if "json" not in ct.lower():
                continue
            schema = ctype.get("schema") or {}
            for v in _make_fuzz_values(schema)[:10]:
                cases.append({"kind": "body", "content_type": ct,
                              "value_type": v["type"], "value": v["value"]})

    cases = cases[:max_cases]
    out["cases_total"] = len(cases)
    anomaly_ids = []

    for case in cases:
        url = endpoint["url"]
        if path_params:
            url = origin + _substitute_path(endpoint["path"], endpoint["parameters"])
        req_headers = dict(headers or {})
        params = {}
        body = None
        if case["kind"] == "query":
            params[case["param"]] = _to_string(case["value"])
        elif case["kind"] == "header":
            req_headers[case["param"]] = _to_string(case["value"])
        elif case["kind"] == "body":
            req_headers["Content-Type"] = case["content_type"]
            body = json.dumps({"__probe__": case["value"]})
        viol = _roe_block(roe_guard, url, endpoint["method"])
        if viol:
            out["cases"].append({"case": case, "blocked": viol})
            continue
        try:
            with httpx.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.request(endpoint["method"], url, params=params or None,
                              headers=req_headers, content=body)
            entry = {"case": case, "status": r.status_code,
                     "body_len": len(r.text or ""),
                     "body_preview": (r.text or "")[:200]}
            out["cases"].append(entry)
            if r.status_code >= 500 and r.status_code < 600:
                out["anomalies"].append({"type": "5xx_error",
                                         "case": case,
                                         "status": r.status_code})
            body_low = (r.text or "").lower()
            if any(sig in body_low for sig in
                   ("sql syntax", "mysql_fetch", "postgresql", "ora-0",
                    "sqlite_", "traceback (most recent call last)",
                    "stack trace", "exception in thread")):
                out["anomalies"].append({"type": "error_signature",
                                         "case": case,
                                         "signature": _first_sig(body_low)})
        except Exception as e:
            out["cases"].append({"case": case, "error": f"{type(e).__name__}: {e}"})

    return out


def _to_string(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (list, dict)):
        return json.dumps(v)
    return str(v)


def _first_sig(body):
    for sig in ("sql syntax", "mysql_fetch", "postgresql", "ora-0",
                "sqlite_", "traceback", "stack trace", "exception"):
        if sig in body:
            return sig
    return "unknown"


def scan(base_url, timeout=10, verify=None, roe_guard=None, headers=None,
         fuzz=True, max_fuzz_per_endpoint=40, max_endpoints=50):
    if verify is None:
        verify = _verify_tls()

    out = {
        "base_url": base_url,
        "spec": None,
        "endpoints": [],
        "auth_schemes": [],
        "coverage": {},
        "fuzz_results": [],
        "anomalies": [],
        "verdict": "UNKNOWN",
        "reason": "",
    }

    disc = discover_spec(base_url, timeout=timeout, verify=verify,
                         roe_guard=roe_guard, headers=headers)
    if disc is None:
        out["reason"] = "no OpenAPI/Swagger spec discovered at common paths"
        return out
    if disc.get("error"):
        out["reason"] = disc["error"]
        return out

    spec = disc["spec"]
    origin = disc["origin"]
    out["spec"] = {"url": disc["url"], "version": disc["version"],
                   "format": disc["format"]}
    if disc.get("discovered_via"):
        out["spec"]["discovered_via"] = disc["discovered_via"]

    endpoints = extract_endpoints(spec, origin)
    out["endpoints"] = [{k: e[k] for k in
                         ("path", "method", "operation_id", "summary",
                          "parameters", "responses", "tags", "url")}
                        for e in endpoints]
    out["auth_schemes"] = extract_auth_schemes(spec)

    documented = {(e["path"], e["method"]) for e in endpoints}
    out["coverage"] = {
        "total_endpoints": len(endpoints),
        "methods": _count_methods(endpoints),
        "tags": _count_tags(endpoints),
        "endpoints_without_security": [
            f"{e['method']} {e['path']}" for e in endpoints
            if not e.get("security")
        ],
        "endpoints_with_params": sum(1 for e in endpoints if e.get("parameters")),
        "endpoints_with_body": sum(1 for e in endpoints if e.get("request_body")),
    }

    if fuzz:
        for endpoint in endpoints[:max_endpoints]:
            r = fuzz_endpoint(endpoint, origin, timeout=timeout,
                              verify=verify, roe_guard=roe_guard,
                              headers=headers,
                              max_cases=max_fuzz_per_endpoint)
            out["fuzz_results"].append({
                "endpoint": r["endpoint"],
                "cases_total": r.get("cases_total", 0),
                "anomalies": len(r.get("anomalies") or []),
            })
            out["anomalies"].extend(r.get("anomalies") or [])

    if out["anomalies"]:
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = (f"{len(out['anomalies'])} anomaly(ies) during fuzzing "
                         f"across {len(endpoints)} endpoints")
    elif endpoints:
        out["verdict"] = "PASS"
        out["reason"] = (f"spec parsed: {len(endpoints)} endpoints, "
                         f"no anomalies during fuzzing")
    return out


def _count_methods(endpoints):
    counts = {}
    for e in endpoints:
        counts[e["method"]] = counts.get(e["method"], 0) + 1
    return counts


def _count_tags(endpoints):
    counts = {}
    for e in endpoints:
        for t in e.get("tags") or []:
            counts[t] = counts.get(t, 0) + 1
    return counts
