"""A1 — Structural JSON/XML injector.

Generates mutated request trees and classifies the server's parser behaviour
via semantic_diff plus a mass-assignment lens. Bounded to 8 mutations per
endpoint, deduped against the paramgraph's mutation_candidates. No
resource-exhaustion patterns: deep nesting is capped at depth 8 and there is
no entity expansion.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from ..diff import BaselineSnapshot, SemanticDiff, build_structure

MAX_MUTATIONS = 8
MAX_NESTING_DEPTH = 8

PROTO_KEYS = ["__proto__", "constructor.prototype"]


@dataclass
class Mutation:
    label: str
    kind: str
    raw_body: str          # serialized JSON (may contain duplicate keys)
    note: str = ""


def _nested(depth):
    obj = "polluted"
    for _ in range(depth):
        obj = {"a": obj}
    return obj


def generate_mutations(base_body, dedupe_against=None):
    """Return up to MAX_MUTATIONS structural mutations of a JSON body.

    base_body: dict (parsed JSON). dedupe_against: paramgraph
    mutation_candidates (list of dicts) whose 'kind' we skip.
    """
    if not isinstance(base_body, dict):
        base_body = {}
    seen_kinds = {c.get("kind") for c in (dedupe_against or [])
                  if isinstance(c, dict)}
    muts = []

    def add(label, kind, obj_or_raw, note=""):
        if kind in seen_kinds:
            return
        raw = (obj_or_raw if isinstance(obj_or_raw, str)
               else json.dumps(obj_or_raw))
        muts.append(Mutation(label=label, kind=kind, raw_body=raw, note=note))

    # Duplicate keys — raw JSON (dict can't hold dups). Pick a telling key.
    dup_key = None
    for cand in ("role", "admin", "is_admin", "id"):
        if cand in base_body:
            dup_key = cand
            break
    dup_key = dup_key or (next(iter(base_body), None) or "role")
    first = json.dumps(base_body.get(dup_key, "user"))
    add("duplicate_key", "duplicate_key",
        '{"' + dup_key + '": ' + first + ', "' + dup_key + '": "admin"}',
        note=f"duplicate '{dup_key}'")

    # Type juggling on an id-ish field
    id_key = None
    for cand in ("id", "user_id", "uid", "account_id"):
        if cand in base_body:
            id_key = cand
            break
    id_key = id_key or "id"
    for label, val in (("ne_operator", {"$ne": None}),
                       ("bool_juggle", True),
                       ("array_juggle", [])):
        body = dict(base_body)
        body[id_key] = val
        add(f"type_juggle_{label}", "type_juggle", body,
            note=f"{id_key}={val!r}")

    # Deep nesting (capped)
    body = dict(base_body)
    body["nested"] = _nested(MAX_NESTING_DEPTH)
    add("deep_nesting", "deep_nesting", body,
        note=f"depth {MAX_NESTING_DEPTH}")

    # Prototype pollution keys
    add("proto_pollution", "proto_pollution",
        {"__proto__": {"polluted": True}}, note="__proto__")
    add("constructor_pollution", "proto_pollution",
        {"constructor": {"prototype": {"polluted": True}}},
        note="constructor.prototype")

    return muts[:MAX_MUTATIONS]


def _snapshot(resp):
    body = (resp or {}).get("body") or ""
    return BaselineSnapshot(
        status=(resp or {}).get("status") or 0, body=body, body_len=len(body),
        structure=build_structure(body, (resp or {}).get("content_type", "")),
        header_names=set(((resp or {}).get("headers") or {}).keys()))


def _accepted(resp):
    s = (resp or {}).get("status")
    return s is not None and 200 <= int(s) < 300


def classify(mutation, baseline_resp, mutation_resp, diff=None):
    """Classify one mutation's response against the baseline."""
    diff = diff or SemanticDiff()
    snap = _snapshot(baseline_resp)
    d = diff.compare(snap, mutation_resp)
    accepted = _accepted(mutation_resp)
    status = (mutation_resp or {}).get("status")
    kind = mutation.kind
    verdict, reason = "PASS", "no divergence"
    severity = "info"
    if kind == "duplicate_key":
        base_body = (baseline_resp or {}).get("body") or ""
        mut_body = (mutation_resp or {}).get("body") or ""
        if "admin" in mut_body and "admin" not in base_body:
            verdict, reason = "SUSPICIOUS", "last-key-wins (admin accepted)"
            severity = "high"
        elif not accepted:
            verdict, reason = "PASS", "duplicate keys rejected"
        else:
            verdict, reason = "SUSPICIOUS", "duplicate keys accepted"
            severity = "medium"
    elif kind == "type_juggle":
        if accepted and (d.structural_delta > 0.1 or d.status_shift > 0):
            verdict, reason = "SUSPICIOUS", \
                "non-scalar type accepted (NoSQL/loose-typing candidate)"
            severity = "high"
        elif accepted:
            verdict, reason = "SUSPICIOUS", "non-scalar type accepted"
            severity = "medium"
    elif kind == "deep_nesting":
        verdict = "PASS"
        reason = ("nested payload accepted (parser tolerant)" if accepted
                  else "nested payload rejected")
    elif kind == "proto_pollution":
        mut_body = (mutation_resp or {}).get("body") or ""
        if accepted and ("polluted" in mut_body or d.status_shift > 0):
            verdict, reason = "SUSPICIOUS", \
                "prototype-pollution key reflected/altered behaviour"
            severity = "high"
    return {"verdict": verdict, "reason": reason, "severity": severity,
            "kind": kind, "label": mutation.label, "note": mutation.note,
            "status": status, "signal_strength": d.signal_strength}


def scan(url, base_body, send, method="POST", mutation_candidates=None,
         diff=None):
    """Run structural injection. send(method, url, raw_body, content_type)
    -> response dict. Returns a result with per-mutation classifications.
    """
    diff = diff or SemanticDiff()
    try:
        baseline_resp = send(method, url,
                             json.dumps(base_body or {}), "application/json")
    except Exception as e:
        return {"verdict": "UNKNOWN", "reason": f"baseline failed: {e}",
                "evidence": {}, "findings": []}
    muts = generate_mutations(base_body, dedupe_against=mutation_candidates)
    findings = []
    for m in muts:
        try:
            resp = send(method, url, m.raw_body, "application/json")
        except Exception as e:
            findings.append({"verdict": "UNKNOWN", "kind": m.kind,
                             "label": m.label, "reason": str(e)})
            continue
        findings.append(classify(m, baseline_resp, resp, diff))
    worst = _worst(findings)
    return {
        "verdict": worst,
        "reason": f"{sum(1 for f in findings if f.get('verdict') == 'SUSPICIOUS')}"
                  f"/{len(findings)} structural mutation(s) diverged",
        "evidence": {"mutations": findings,
                     "count": len(findings)},
        "findings": findings,
    }


def _worst(findings):
    order = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    best = "PASS"
    for f in findings:
        if order.get(f.get("verdict"), 0) > order.get(best, 0):
            best = f.get("verdict")
    return best


__all__ = ["Mutation", "generate_mutations", "classify", "scan",
           "MAX_MUTATIONS", "MAX_NESTING_DEPTH"]
