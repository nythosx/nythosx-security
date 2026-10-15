"""A3 — GraphQL depth module.

Extends graphql_deep coverage:
  * introspection dump -> graphql_introspection_exposed
  * alias batching (2-4 aliases, single query — never resource-exhausting)
  * field-suggestion extraction from "Did you mean ..." errors
  * mutation discovery on endpoints the crawl marked read-only

Every request routes through the provided `post` callable (engine.http). No
deeply-nested or high-fanout queries; alias count is hard-capped.
"""
from __future__ import annotations

import json
import re

MAX_ALIASES = 4
MIN_ALIASES = 2

_DID_YOU_MEAN_RE = re.compile(r'Did you mean\s+(?:to use\s+)?["\']?'
                              r'([A-Za-z0-9_, "\'()]+?)["\']?\s*\?',
                              re.IGNORECASE)
_SUGGEST_FIELD_RE = re.compile(r'["\']([A-Za-z_][A-Za-z0-9_]*)["\']')

INTROSPECTION_QUERY = (
    '{"query":"{ __schema { queryType { name } types { name } } }"}')


def _json(resp):
    body = (resp or {}).get("body") or ""
    try:
        return json.loads(body)
    except Exception:
        return None


def introspection(url, post):
    """Return a finding if introspection is enabled."""
    resp = post(url, INTROSPECTION_QUERY)
    data = _json(resp)
    enabled = bool(data and isinstance(data, dict)
                   and (data.get("data") or {}).get("__schema"))
    if enabled:
        types = ((data["data"]["__schema"].get("types")) or [])
        return {"verdict": "VULNERABLE", "severity": "medium",
                "type": "graphql_introspection_exposed",
                "reason": f"introspection enabled ({len(types)} types)",
                "evidence": {"type_count": len(types)}}
    return {"verdict": "PASS", "type": "graphql_introspection",
            "reason": "introspection disabled or unavailable"}


def alias_batch_query(field, n):
    n = max(MIN_ALIASES, min(MAX_ALIASES, n))
    aliases = ",".join(f'a{i}:{field}' for i in range(n))
    return '{"query":"{ ' + aliases + ' }"}'


def alias_batching(url, post, field="__typename", n=MAX_ALIASES):
    """Single query with 2-4 aliases. Accepted batch -> candidate."""
    resp = post(url, alias_batch_query(field, n))
    data = _json(resp)
    ok = bool(data and isinstance(data, dict) and data.get("data"))
    return {"verdict": "SUSPICIOUS" if ok else "PASS",
            "severity": "low" if ok else "info",
            "type": "graphql_alias_batching",
            "reason": (f"server executed {min(n, MAX_ALIASES)} aliases in one "
                       f"query (batching allowed)" if ok
                       else "alias batching rejected"),
            "evidence": {"aliases": min(n, MAX_ALIASES)}}


def extract_field_suggestions(error_text):
    """Mine 'Did you mean ...' hints for hidden field names."""
    fields = set()
    for m in _DID_YOU_MEAN_RE.finditer(error_text or ""):
        for fm in _SUGGEST_FIELD_RE.finditer(m.group(1)):
            fields.add(fm.group(1))
        for token in re.split(r"[,\s]+", m.group(1)):
            token = token.strip().strip("\"'")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token or ""):
                fields.add(token)
    return sorted(fields)


def field_suggestions(url, post, bogus_field="zzz_nope_field"):
    resp = post(url, '{"query":"{ ' + bogus_field + ' }"}')
    body = (resp or {}).get("body") or ""
    fields = extract_field_suggestions(body)
    if fields:
        return {"verdict": "SUSPICIOUS", "severity": "medium",
                "type": "graphql_field_suggestion",
                "reason": f"error messages leak {len(fields)} field name(s)",
                "evidence": {"suggested_fields": fields}}
    return {"verdict": "PASS", "type": "graphql_field_suggestion",
            "reason": "no field suggestions in errors"}


def mutation_discovery(url, post, read_only=True):
    """Probe whether mutations are reachable on a read-only endpoint."""
    resp = post(url, '{"query":"mutation { __typename }"}')
    data = _json(resp)
    body = (resp or {}).get("body") or ""
    # A schema that exposes a mutation root (no 'mutations are not supported')
    allowed = bool(data and isinstance(data, dict) and data.get("data")) or (
        "mutation" in body.lower() and "not supported" not in body.lower()
        and "cannot query" not in body.lower())
    if allowed and read_only:
        return {"verdict": "SUSPICIOUS", "severity": "high",
                "type": "graphql_mutation_exposed",
                "reason": "mutations reachable on a read-only-marked endpoint",
                "evidence": {}}
    return {"verdict": "PASS", "type": "graphql_mutation_discovery",
            "reason": "no unexpected mutation surface"}


def scan(url, post, read_only=True):
    findings = [
        introspection(url, post),
        alias_batching(url, post),
        field_suggestions(url, post),
        mutation_discovery(url, post, read_only=read_only),
    ]
    order = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    worst = max(findings, key=lambda f: order.get(f.get("verdict"), 0))
    return {
        "verdict": worst.get("verdict", "PASS"),
        "reason": worst.get("reason", ""),
        "evidence": {"graphql": findings},
        "findings": [f for f in findings
                     if f.get("verdict") in ("VULNERABLE", "SUSPICIOUS")],
    }


__all__ = ["introspection", "alias_batching", "alias_batch_query",
           "extract_field_suggestions", "field_suggestions",
           "mutation_discovery", "scan", "MAX_ALIASES", "MIN_ALIASES"]
