from __future__ import annotations

import re
import time

import httpx

from .chain_engine import register_tool
from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


CAPABILITY = Capability(
    name="graphql_schema_walk",
    description=("Reconstruct GraphQL schema by iteratively using field-"
                 "suggestion hints ('Did you mean X?') when introspection "
                 "is disabled. Rebuilds field names, then recurses."),
    category="recon",
    cost="medium",
    destructive=False,
    idempotent=True,
)


SEED_FIELDS = [
    "me", "user", "viewer", "account", "profile", "node",
    "users", "accounts", "nodes", "session", "currentUser",
    "getUser", "getUsers", "listUsers",
    "post", "posts", "item", "items", "product", "products",
    "order", "orders", "search",
    "cart", "coupon", "payment", "invoice", "transaction",
    "admin", "config", "settings",
]

_TYPENAME_PROBE = "{ __typename }"
_SUGGEST_RE = re.compile(
    r"""[Dd]id you mean\s+\\?['"]?([A-Za-z_][A-Za-z0-9_]*)""")
_UNKNOWN_FIELD_RE = re.compile(
    r"""(?:Cannot query field|Unknown field|Field)\s+['"]?([A-Za-z_][A-Za-z0-9_]*)""",
    re.I,
)


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return False


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


def _post(endpoint, query, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, endpoint, "POST")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    h = dict(headers or {})
    h.setdefault("Content-Type", "application/json")
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(endpoint, json={"query": query}, headers=h)
        return {"status": r.status_code, "body": (r.text or "")[:4000]}
    except _http.ConnectError as e:
        return {"status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _extract_suggestion(body):
    if not body:
        return None
    m = _SUGGEST_RE.search(body)
    if m:
        return m.group(1)
    return None


def _probe_field(endpoint, field, headers, timeout, verify, roe_guard):
    """Returns (accepted_bool, suggested_field_or_None, raw_response)."""
    query = "{ " + field + " { __typename } }"
    r = _post(endpoint, query, headers, timeout, verify, roe_guard)
    if r.get("blocked"):
        return None, None, r
    if r.get("status") is None:
        return False, None, r
    body = r.get("body") or ""
    import json as _json
    try:
        data = _json.loads(body)
    except Exception:
        return False, None, r
    if "data" in data and isinstance(data.get("data"), dict):
        if field in data["data"]:
            return True, None, r
    errors = data.get("errors") or []
    for e in errors:
        msg = str(e.get("message") or "")
        s = _SUGGEST_RE.search(msg)
        if s:
            return False, s.group(1), r
    return False, None, r


def discover_fields(endpoint, headers=None, timeout=8, roe_guard=None,
                    max_fields=40, max_probes=200):
    verify = _verify_tls()
    probe_count = 0
    discovered = []
    suggestions_used = set()

    queue = list(SEED_FIELDS)
    tried = set()

    while queue and len(discovered) < max_fields and probe_count < max_probes:
        field = queue.pop(0)
        if field in tried:
            continue
        tried.add(field)
        probe_count += 1
        accepted, suggestion, _r = _probe_field(
            endpoint, field, headers, timeout, verify, roe_guard)
        if accepted is None:
            return {"error": "ROE_BLOCK"}
        if accepted:
            discovered.append(field)
            continue
        if suggestion and suggestion not in tried and suggestion not in suggestions_used:
            suggestions_used.add(suggestion)
            queue.insert(0, suggestion)

    return {
        "endpoint": endpoint,
        "discovered_fields": discovered,
        "probes_used": probe_count,
        "suggestions_followed": sorted(suggestions_used),
    }


def scan(endpoint, headers=None, timeout=8, roe_guard=None,
         max_fields=40, max_probes=200):
    verify = _verify_tls()
    viol = _roe_block(roe_guard, endpoint, "POST")
    if viol:
        return ScanResult(
            capability="graphql_schema_walk", target=endpoint,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )
    probe = _post(endpoint, _TYPENAME_PROBE, headers, timeout, verify, roe_guard)
    if probe.get("blocked"):
        return ScanResult(
            capability="graphql_schema_walk", target=endpoint,
            verdict="UNKNOWN", reason=probe["error"],
        )
    if probe.get("status") is None:
        return ScanResult(
            capability="graphql_schema_walk", target=endpoint,
            verdict="UNKNOWN", reason=probe.get("error", "no response"),
        )
    body = probe.get("body") or ""
    if "__typename" not in body and "data" not in body:
        return ScanResult(
            capability="graphql_schema_walk", target=endpoint,
            verdict="UNKNOWN",
            reason="endpoint does not respond like GraphQL",
            evidence={"preview": body[:200]},
        )

    result = discover_fields(endpoint, headers=headers, timeout=timeout,
                              roe_guard=roe_guard, max_fields=max_fields,
                              max_probes=max_probes)
    if "error" in result:
        return ScanResult(
            capability="graphql_schema_walk", target=endpoint,
            verdict="UNKNOWN", reason=result["error"],
        )
    fields = result.get("discovered_fields") or []
    suggestions = result.get("suggestions_followed") or []

    if not fields:
        return ScanResult(
            capability="graphql_schema_walk", target=endpoint,
            verdict="PASS", severity="low",
            reason=(f"no root fields discovered in "
                    f"{result.get('probes_used', 0)} probes"),
            evidence=result,
        )
    return ScanResult(
        capability="graphql_schema_walk", target=endpoint,
        verdict="SUSPICIOUS", severity="medium",
        reason=(f"reconstructed {len(fields)} root field(s) "
                f"using {len(suggestions)} suggestion hint(s) "
                f"({result.get('probes_used', 0)} probes)"),
        evidence=result,
    )


def dump_all_data(endpoint, headers=None, timeout=10, roe_guard=None,
                   max_records=100):
    """Given a GraphQL endpoint, dump every accessible root field."""
    verify = _verify_tls()
    viol = _roe_block(roe_guard, endpoint, "POST")
    if viol:
        return {"error": f"ROE_BLOCK: {viol}"}

    probe = _post(endpoint, "{ __schema { queryType { name fields { name type { name kind } } } } }",
                  headers, timeout, verify, roe_guard)
    if not probe or probe.get("status") != 200:
        return {"error": "introspection failed"}
    body = probe.get("body") or ""
    if "__schema" not in body:
        return {"error": "introspection disabled or no schema returned"}
    import json as _json
    try:
        data = _json.loads(body)
    except Exception:
        return {"error": "invalid JSON in introspection response"}

    schema = (data.get("data") or {}).get("__schema") or {}
    q_type = (schema.get("queryType") or {})
    fields = q_type.get("fields") or []

    dumped = {}
    total_records = 0
    for field in fields:
        fname = field.get("name")
        if not fname or fname.startswith("__"):
            continue
        query = "{ " + fname + " { __typename } }"
        r = _post(endpoint, query, headers, timeout, verify, roe_guard)
        if r.get("status") != 200:
            continue
        b = r.get("body") or ""
        if "errors" in b and "data" not in b:
            continue
        try:
            parsed = _json.loads(b)
        except Exception:
            continue
        payload = (parsed.get("data") or {}).get(fname)
        if payload is None:
            continue
        dumped[fname] = payload
        if isinstance(payload, list):
            total_records += len(payload)
        elif isinstance(payload, dict):
            total_records += 1
        if total_records >= max_records:
            break
    return {"dumped_types": list(dumped.keys()),
            "total_records": total_records,
            "sample": {k: v for k, v in list(dumped.items())[:3]}}


def _tool_graphql_dump(orch, args):
    endpoint = (args.get("url") or orch.get_context("graphql_url")
                or orch.target)
    result = dump_all_data(endpoint, roe_guard=orch.roe_guard)
    if result.get("error"):
        return {"verdict": "UNKNOWN", "reason": result["error"]}
    dumped = result.get("dumped_types") or []
    records = result.get("total_records") or 0
    if not dumped:
        return {"verdict": "PASS",
                "reason": "introspection succeeded but no data returned"}
    return {
        "verdict": "VULNERABLE" if records >= 3 else "SUSPICIOUS",
        "reason": (f"GraphQL introspection dumped {len(dumped)} type(s) "
                    f"and {records} record(s)"),
        "evidence": result,
    }


register_tool("graphql_dump", _tool_graphql_dump)

__all__ = ["scan", "discover_fields", "CAPABILITY",
           "SEED_FIELDS", "dump_all_data"]
