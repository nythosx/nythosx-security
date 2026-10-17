import json
import re
import time

import httpx

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql",
    "/graphql/v1", "/api/v1/graphql", "/index.php?graphql",
]

INTROSPECTION_PROBE = "{ __typename }"

APOLLO_DIRECTIVES = ["@authenticated", "@requiresScopes", "@policy"]

TYPENAME = "__typename"


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="POST"):
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


def _post(endpoint, payload, headers, timeout, verify, roe_guard,
          content_type="application/json"):
    viol = _roe_block(roe_guard, endpoint, "POST")
    if viol:
        return {"status": None, "error": f"ROE_BLOCK: {viol}", "blocked": True}
    h = dict(headers or {})
    h["Content-Type"] = content_type
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if content_type == "application/json":
                r = c.post(endpoint, json=payload, headers=h)
            else:
                r = c.post(endpoint, data=payload, headers=h)
        return {"status": r.status_code,
                "body": (r.text or "")[:4000],
                "content_type": r.headers.get("Content-Type", ""),
                "headers": dict(r.headers)}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


GRAPHQL_ERROR_SIGNATURES = (
    "cannot query field",
    "syntax error",
    "unknown field",
    "field '",
    "expected name",
)


def _looks_like_graphql_errors(errors):
    if not isinstance(errors, list) or not errors:
        return False
    for e in errors[:5]:
        if not isinstance(e, dict):
            continue
        msg = str(e.get("message", "")).lower()
        if any(sig in msg for sig in GRAPHQL_ERROR_SIGNATURES):
            return True
        if "locations" in e or "path" in e or "extensions" in e:
            return True
    return False


def _is_graphql_response(resp):
    if not resp or resp.get("status") is None:
        return False
    body = (resp.get("body") or "").strip()
    if not body:
        return False
    try:
        data = json.loads(body)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    if "data" in data and data["data"] is not None:
        return True
    if "errors" in data and _looks_like_graphql_errors(data["errors"]):
        return True
    return False



def _preflight(url, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, "POST")
    if viol:
        return {"reachable": False, "blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(url, json={"query": "{ __typename }"},
                       headers=dict(headers or {}, **{"Content-Type": "application/json"}))
        return {"reachable": True, "status": r.status_code,
                "content_type": r.headers.get("Content-Type", ""),
                "body": (r.text or "")[:400]}
    except _http.ConnectError as e:
        return {"reachable": False, "error": f"Connection refused: {e}"}
    except _http.TimeoutException:
        return {"reachable": False, "error": "Connection timed out"}
    except Exception as e:
        return {"reachable": False, "error": f"{type(e).__name__}: {e}"}

def detect_endpoint(base_url, headers=None, timeout=10, roe_guard=None, verify=None):
    if verify is None:
        verify = _verify_tls()
    base = base_url.rstrip("/")
    if any(base.endswith(p) for p in GRAPHQL_PATHS):
        pre = _preflight(base, headers, timeout, verify, roe_guard)
        if not pre.get("reachable"):
            return {"error": pre.get("error", "target unreachable")}
        return {"url": base, "preflight_status": pre.get("status")}
    for path in GRAPHQL_PATHS:
        url = base + path
        probe = {"query": INTROSPECTION_PROBE}
        resp = _post(url, probe, headers, timeout, verify, roe_guard)
        if resp.get("blocked"):
            return {"error": resp["error"]}
        if not _is_graphql_response(resp):
            continue
        try:
            body = json.loads(resp.get("body") or "")
        except Exception:
            continue
        data = body.get("data")
        if isinstance(data, dict) and TYPENAME.lstrip("_") in str(data):
            return {"url": url, "probe_status": resp["status"]}
        if isinstance(data, dict) and TYPENAME in str(data):
            return {"url": url, "probe_status": resp["status"]}
        if isinstance(data, dict) and data:
            return {"url": url, "probe_status": resp["status"]}
        if body.get("errors") and _looks_like_graphql_errors(body["errors"]):
            return {"url": url, "probe_status": resp["status"]}
    return None


def _extract_types(introspection_data):
    types = []
    data = (introspection_data or {}).get("data") or {}
    schema = data.get("__schema") or {}
    for t in schema.get("types") or []:
        name = t.get("name") or ""
        if name.startswith("__"):
            continue
        kind = t.get("kind") or ""
        fields = [f.get("name") for f in (t.get("fields") or []) if f.get("name")]
        types.append({"name": name, "kind": kind, "fields": fields})
    return types


def run_introspection(endpoint, headers, timeout, verify, roe_guard):
    query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          kind
          name
          fields { name }
        }
        directives { name }
      }
    }
    """
    resp = _post(endpoint, {"query": query}, headers, timeout, verify, roe_guard)
    if resp.get("blocked"):
        return {"error": resp["error"]}
    if resp.get("status") is None:
        return {"error": f"target unreachable: {resp.get('error', 'no response')[:120]}"}
    if not _is_graphql_response(resp):
        body = (resp.get("body") or "").strip()[:200]
        ct = resp.get("content_type", "")
        return {"error": f"non-GraphQL response (HTTP {resp.get('status')}, "
                         f"Content-Type={ct!r}, body={body!r})"}
    try:
        data = json.loads(resp["body"])
    except Exception:
        return {"error": "invalid JSON"}
    if data.get("errors") and not data.get("data"):
        return {"error": "introspection disabled",
                "errors": [e.get("message") for e in data["errors"][:3]]}
    types = _extract_types(data)
    schema = (data.get("data") or {}).get("__schema") or {}
    directives = [d.get("name") for d in (schema.get("directives") or [])]
    apollo_hits = [d for d in directives
                   if any(a.lstrip("@") in d for a in APOLLO_DIRECTIVES)]
    return {"types": types, "directives": directives, "apollo_directives": apollo_hits}


def _find_recursive_field(types):
    for t in types:
        for f in t.get("fields") or []:
            if f.lower() in ("friends", "posts", "comments", "children",
                             "related", "edges", "nodes", "users", "items"):
                return f
    for t in types:
        fields = t.get("fields") or []
        if fields:
            return fields[0]
    return None



COMMON_ROOT_FIELDS = [
    "user", "users", "me", "viewer", "node", "nodes", "account",
    "accounts", "post", "posts", "item", "items", "product", "products",
    "order", "orders", "search", "query", "getUser", "getUsers",
    "profile", "profiles", "session", "currentUser",
]


def discover_root_fields(endpoint, headers, timeout, verify, roe_guard):
    found = []
    for name in COMMON_ROOT_FIELDS:
        probe = "{ " + name + " { " + TYPENAME + " } }"
        resp = _post(endpoint, {"query": probe}, headers, timeout, verify, roe_guard)
        if resp.get("blocked"):
            return found
        if not _is_graphql_response(resp):
            continue
        try:
            body = json.loads(resp.get("body") or "")
        except Exception:
            continue
        if body.get("data") and isinstance(body["data"], dict) and name in body["data"]:
            found.append(name)
    return found

def _build_nested_query(field, depth):
    inner = TYPENAME
    q = inner
    for _ in range(depth):
        q = f"{field} {{ {q} }}"
    return "{ " + q + " }"


def depth_limit_probe(endpoint, recursive_field, headers, timeout, verify,
                      roe_guard, max_depth=110):
    if not recursive_field:
        return {"verdict": "UNKNOWN",
                "reason": "no recursive field discovered; cannot probe depth",
                "evidence": {}}

    small = _post(endpoint,
                  {"query": _build_nested_query(recursive_field, 3)},
                  headers, timeout, verify, roe_guard)
    if not _is_graphql_response(small):
        return {"verdict": "UNKNOWN",
                "reason": "shallow probe did not return a GraphQL response",
                "evidence": {"status": small.get("status")}}

    deep = _post(endpoint,
                 {"query": _build_nested_query(recursive_field, max_depth)},
                 headers, timeout, verify, roe_guard)
    if deep.get("status") is None:
        if deep.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": deep["error"], "evidence": {}}
        return {"verdict": "SUSPICIOUS",
                "reason": f"depth-{max_depth} query caused a connection failure "
                          f"(possible timeout)",
                "evidence": {"error": deep.get("error", "")[:200]}}

    body = deep.get("body") or ""
    if deep.get("status") == 200 and '"data"' in body and '"errors"' not in body[:500]:
        return {"verdict": "VULNERABLE",
                "reason": f"depth-{max_depth} query completed successfully "
                          f"(no depth limit enforced)",
                "evidence": {"depth": max_depth, "field": recursive_field,
                             "preview": body[:300]}}
    low = body.lower()
    depth_keywords = ["depth", "too deep", "max depth", "complexity",
                      "query is too complex", "exceeds maximum"]
    if any(k in low for k in depth_keywords):
        return {"verdict": "PASS",
                "reason": "server rejected deep query (depth limit present)",
                "evidence": {"preview": body[:200]}}

    if "Cannot query field" in body or "Unknown field" in body:
        return {"verdict": "UNKNOWN",
                "reason": f"recursive field '{recursive_field}' not accepted; "
                          f"depth not testable",
                "evidence": {"field": recursive_field}}
    return {"verdict": "UNKNOWN",
            "reason": f"deep query response unclear (HTTP {deep.get('status')})",
            "evidence": {"preview": body[:300]}}


def batch_array_probe(endpoint, recursive_field, headers, timeout, verify,
                      roe_guard, batch_size=50):
    if not recursive_field:
        return {"verdict": "UNKNOWN",
                "reason": "no field available for batching test", "evidence": {}}
    inner = _build_nested_query(recursive_field, 3)
    payload = [{"query": inner} for _ in range(batch_size)]
    resp = _post(endpoint, payload, headers, timeout, verify, roe_guard)
    if resp.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": resp["error"], "evidence": {}}
    body = resp.get("body") or ""
    try:
        data = json.loads(body)
    except Exception:
        return {"verdict": "UNKNOWN",
                "reason": "response was not JSON; array batching not supported",
                "evidence": {"preview": body[:200]}}

    if isinstance(data, list):
        successful = sum(1 for item in data
                         if isinstance(item, dict) and "data" in item)
        if successful >= batch_size:
            return {"verdict": "VULNERABLE",
                    "reason": f"array batch of {batch_size} operations accepted "
                              f"and executed",
                    "evidence": {"batch_size": batch_size,
                                 "executed": successful}}
        if successful > 0:
            return {"verdict": "SUSPICIOUS",
                    "reason": f"{successful}/{batch_size} batched operations "
                              f"executed",
                    "evidence": {"executed": successful}}
        return {"verdict": "PASS",
                "reason": "batched array rejected or all operations failed",
                "evidence": {"preview": body[:200]}}

    if isinstance(data, dict) and data.get("errors"):
        msgs = " ".join(str(e.get("message", "")) for e in data["errors"][:3]).lower()
        if "batch" in msgs or "array" in msgs or "multiple operations" in msgs:
            return {"verdict": "PASS",
                    "reason": "server rejects array batching",
                    "evidence": {"messages": msgs[:200]}}
    return {"verdict": "UNKNOWN",
            "reason": "server did not return a JSON array; array batching not enabled",
            "evidence": {"preview": body[:200]}}


def batch_alias_probe(endpoint, recursive_field, headers, timeout, verify,
                      roe_guard, alias_count=50):
    if not recursive_field:
        return {"verdict": "UNKNOWN",
                "reason": "no field available for alias batching", "evidence": {}}
    inner = _build_nested_query(recursive_field, 2)
    inner_body = inner.strip()[2:-2] if inner.startswith("{ ") else inner
    aliased = "{ " + " ".join(f"a{i}: {inner_body.strip()}"
                              for i in range(alias_count)) + " }"
    resp = _post(endpoint, {"query": aliased}, headers, timeout, verify, roe_guard)
    if resp.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": resp["error"], "evidence": {}}
    body = resp.get("body") or ""
    try:
        data = json.loads(body)
    except Exception:
        return {"verdict": "UNKNOWN",
                "reason": "response not JSON", "evidence": {}}
    response_data = data.get("data") or {}
    resolved = sum(1 for k in response_data.keys() if k.startswith("a"))
    if resolved >= alias_count * 0.9:
        return {"verdict": "VULNERABLE",
                "reason": f"{resolved} aliased operations resolved in one request "
                          f"(rate limit bypassable)",
                "evidence": {"alias_count": alias_count, "resolved": resolved}}
    if resolved > 0:
        return {"verdict": "SUSPICIOUS",
                "reason": f"{resolved}/{alias_count} aliases resolved",
                "evidence": {"resolved": resolved}}
    return {"verdict": "PASS",
            "reason": "no aliases resolved",
            "evidence": {"preview": body[:200]}}


def csrf_form_probe(endpoint, recursive_field, headers, timeout, verify, roe_guard):
    if not recursive_field:
        return {"verdict": "UNKNOWN",
                "reason": "no field available for CSRF test", "evidence": {}}
    query = _build_nested_query(recursive_field, 2)
    form_body = "query=" + query.replace(" ", "+").replace("{", "%7B").replace("}", "%7D")
    resp = _post(endpoint, form_body, headers, timeout, verify, roe_guard,
                 content_type="application/x-www-form-urlencoded")
    if resp.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": resp["error"], "evidence": {}}
    if _is_graphql_response(resp):
        return {"verdict": "VULNERABLE",
                "reason": "endpoint accepted application/x-www-form-urlencoded — "
                          "CSRF via simple form POST is possible",
                "evidence": {"content_type": "application/x-www-form-urlencoded",
                             "preview": (resp.get("body") or "")[:300]}}
    return {"verdict": "PASS",
            "reason": "endpoint rejected non-JSON content type",
            "evidence": {"status": resp.get("status"),
                         "content_type": resp.get("content_type", "")}}


def apollo_federation_probe(endpoint, types, headers, timeout, verify, roe_guard):
    interface_types = [t for t in types if t.get("kind") == "INTERFACE"]
    if not interface_types:
        return {"verdict": "UNKNOWN",
                "reason": "no interface types in schema; CVE-2025-64530 not testable",
                "evidence": {}}
    import json as _json
    findings = []
    tested = 0
    for it in interface_types[:3]:
        iface_name = it.get("name") or ""
        fields = it.get("fields") or []
        if not iface_name or not fields:
            continue
        field = fields[0]
        queries = [
            ("direct",
             ('{ __type(name: "' + iface_name +
              '") { name kind fields { name } } }')),
            ("inline_fragment",
             ('{ __typename }')),
        ]
        for label, q in queries:
            tested += 1
            r = _post(endpoint, {"query": q}, headers, timeout,
                      verify, roe_guard)
            if r.get("blocked"):
                return {"verdict": "UNKNOWN",
                        "reason": r.get("error", "ROE_BLOCK"),
                        "evidence": {}}
            if r.get("status") is None:
                continue
            body = r.get("body") or ""
            try:
                data = _json.loads(body)
            except Exception:
                continue
            if data.get("data") and not data.get("errors"):
                findings.append({
                    "interface": iface_name,
                    "field": field,
                    "test": label,
                    "status": r.get("status"),
                    "preview": body[:200],
                })
    if findings:
        return {
            "verdict": "SUSPICIOUS",
            "reason": (f"CVE-2025-64530 candidate: {len(findings)} "
                       f"interface field(s) reached without directive "
                       f"enforcement across {tested} probe(s)"),
            "evidence": {"findings": findings,
                         "cve": "CVE-2025-64530",
                         "remediation": ("upgrade federation composition to "
                                          "2.9.5 / 2.10.4 / 2.11.5 / 2.12.1")},
        }
    return {
        "verdict": "PASS",
        "reason": (f"{len(interface_types)} interface type(s) found; "
                   f"no direct-query bypass observed across {tested} probe(s)"),
        "evidence": {"interfaces_tested": min(len(interface_types), 3)},
    }


def field_suggestion_probe(endpoint, recursive_field, headers, timeout, verify,
                           roe_guard):
    typo_payloads = [
        (recursive_field, recursive_field + "sx") if recursive_field else None,
        ("user", "userss"),
        ("getUser", "getUserz"),
        ("me", "mex"),
    ]
    for _real, typo in [t for t in typo_payloads if t]:
        resp = _post(endpoint,
                     {"query": "{ " + typo + " { " + TYPENAME + " } }"},
                     headers, timeout, verify, roe_guard)
        if resp.get("blocked"):
            return {"verdict": "UNKNOWN", "reason": resp["error"], "evidence": {}}
        body = resp.get("body") or ""
        if "Did you mean" in body or "did you mean" in body.lower():
            match = re.search(r'[Dd]id you mean[^"]*?"([^"]+)"', body)
            suggested = match.group(1) if match else ""
            return {"verdict": "SUSPICIOUS",
                    "reason": f"endpoint leaks field names via 'Did you mean' "
                              f"hint (schema enumeration possible even without "
                              f"introspection)",
                    "evidence": {"typo": typo, "suggestion": suggested,
                                 "preview": body[:300]}}
    return {"verdict": "PASS",
            "reason": "no 'Did you mean' suggestions leaked",
            "evidence": {}}


SENSITIVE_GRAPHQL_FIELDS = [
    "email", "role", "isAdmin", "is_admin", "ssn", "phone", "address",
    "password", "passwordHash", "apiKey", "api_key", "internalNotes",
    "internal_notes", "deletedAt", "deleted_at",
]

ROOT_FIELD_CANDIDATES_FOR_AUTHZ = [
    "me", "user", "viewer", "account", "profile", "currentUser", "users",
]


def field_authz_probe(endpoint, headers, timeout, verify, roe_guard):
    findings = []
    attempts = []
    for root in ROOT_FIELD_CANDIDATES_FOR_AUTHZ[:4]:
        for field in SENSITIVE_GRAPHQL_FIELDS[:8]:
            query = "{ " + root + " { " + field + " } }"
            resp = _post(endpoint, {"query": query}, headers, timeout,
                         verify, roe_guard)
            if resp.get("blocked"):
                return {"verdict": "UNKNOWN",
                        "reason": f"ROE_BLOCK: {resp.get('error', '')}",
                        "evidence": {"attempts": attempts}}
            if not _is_graphql_response(resp):
                continue
            attempts.append({"root": root, "field": field,
                             "status": resp.get("status")})
            try:
                data = json.loads(resp.get("body") or "")
            except Exception:
                continue
            payload = (data.get("data") or {}).get(root)
            if not isinstance(payload, dict):
                continue
            value = payload.get(field)
            if value is None:
                continue
            if isinstance(value, str) and len(value) > 3:
                findings.append({"root": root, "field": field,
                                  "value_preview": value[:60]})
            elif isinstance(value, (int, float, bool)):
                findings.append({"root": root, "field": field,
                                  "value": value})
            if len(findings) >= 5:
                break
        if len(findings) >= 5:
            break

    if findings:
        return {
            "verdict": "VULNERABLE", "severity": "high",
            "reason": (f"{len(findings)} sensitive field(s) readable in the "
                        f"current auth context"),
            "evidence": {"findings": findings, "attempts": attempts[:20]},
        }
    if not attempts:
        return {"verdict": "UNKNOWN",
                "reason": "no GraphQL response to field_authz probes",
                "evidence": {"attempts": attempts}}
    return {"verdict": "PASS",
            "reason": f"no sensitive fields returned across {len(attempts)} query(ies)",
            "evidence": {"attempts": attempts[:20]}}


def _scan_impl(base_url, headers=None, timeout=15, roe_guard=None, verify=None,
         max_depth=110, batch_size=50):
    if verify is None:
        verify = _verify_tls()

    det = detect_endpoint(base_url, headers, timeout, roe_guard, verify)
    if det is None:
        return {"endpoint": None,
                "verdict": "UNKNOWN",
                "reason": "no GraphQL endpoint detected at common paths",
                "results": {}}
    if isinstance(det, dict) and det.get("error"):
        reason = det["error"]
        if "ROE_BLOCK" in reason:
            reason = f"ROE_BLOCK: {reason.split('ROE_BLOCK:', 1)[-1].strip()}"
        return {"endpoint": None,
                "verdict": "UNKNOWN",
                "reason": reason,
                "results": {}}

    endpoint = det["url"]
    intro = run_introspection(endpoint, headers, timeout, verify, roe_guard)

    if intro.get("error"):
        types = []
        discovered = discover_root_fields(endpoint, headers, timeout, verify, roe_guard)
        recursive_field = discovered[0] if discovered else None
        intro["fallback_fields"] = discovered
    else:
        types = intro.get("types") or []
        recursive_field = _find_recursive_field(types)
        if not recursive_field:
            discovered = discover_root_fields(endpoint, headers, timeout, verify, roe_guard)
            if discovered:
                recursive_field = discovered[0]
                intro["fallback_fields"] = discovered

    results = {
        "introspection": intro,
        "recursive_field": recursive_field,
    }

    results["depth_limit"] = depth_limit_probe(
        endpoint, recursive_field, headers, timeout, verify, roe_guard, max_depth)
    results["batch_array"] = batch_array_probe(
        endpoint, recursive_field, headers, timeout, verify, roe_guard, batch_size)
    results["batch_alias"] = batch_alias_probe(
        endpoint, recursive_field, headers, timeout, verify, roe_guard, batch_size)
    results["csrf_form"] = csrf_form_probe(
        endpoint, recursive_field, headers, timeout, verify, roe_guard)
    results["apollo_federation"] = apollo_federation_probe(
        endpoint, types, headers, timeout, verify, roe_guard)
    results["field_suggestion"] = field_suggestion_probe(
        endpoint, recursive_field, headers, timeout, verify, roe_guard)
    results["field_authz"] = field_authz_probe(
        endpoint, headers, timeout, verify, roe_guard)

    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    overall = "UNKNOWN"
    for key in ("depth_limit", "batch_array", "batch_alias", "csrf_form",
                "apollo_federation", "field_suggestion", "field_authz"):
        r = results.get(key) or {}
        if rank.get(r.get("verdict"), 0) > rank.get(overall, 0):
            overall = r["verdict"]

    return {"endpoint": endpoint,
            "verdict": overall,
            "reason": f"overall verdict across {len(results)-2} probes",
            "results": results}

def scan(*args, **kwargs):
    from .contract import make_result
    raw = _scan_impl(*args, **kwargs)
    return make_result(raw, capability="graphql_security", args=args, kwargs=kwargs)
