"""Param Context Graph — typed parameter model.

Replaces flat param-name strings with typed nodes that carry where a param
was observed, what value types it accepts, whether it reflects, which auth
contexts saw it, and the result of a type-inference oracle.

The oracle sends six canonical probes (1, 1.5, abc, [], {}, null) and
classifies the param by which probes the endpoint accepts versus rejects:

  strict_numeric   numeric accepted, strings 4xx  -> arithmetic / numeric
                   injection candidate
  loose_string     everything accepted            -> injection-family
                   candidate
  container_typed  empty array/object accepted but scalars rejected ->
                   NoSQL / mass-assignment candidate

Classification drives chain selection: instead of spraying every injection
family at every param, chains trigger on the family facts this module emits.

Every probe goes through engine.http (shared rate limiter + scope gate);
callers that want to unit-test the logic inject their own probe_runner.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .diff import BaselineSnapshot, SemanticDiff, build_structure

SOURCES = ["url", "body", "header", "cookie", "graphql", "json_path"]
OBSERVED_TYPES = ["int", "float", "string", "email", "uuid", "url",
                  "base64", "jwt", "filename", "bool", "enum"]
AUTH_CONTEXTS = ["anon", "user_a", "user_b", "admin"]

CLASS_STRICT_NUMERIC = "strict_numeric"
CLASS_LOOSE_STRING = "loose_string"
CLASS_CONTAINER_TYPED = "container_typed"
CLASS_UNKNOWN = "unknown"

# (label, kind, query-string form, json value)
CANONICAL_PROBES = [
    ("int", "numeric", "1", 1),
    ("float", "numeric", "1.5", 1.5),
    ("string", "string", "abc", "abc"),
    ("array", "container", "[]", []),
    ("object", "container", "{}", {}),
    ("null", "null", "null", None),
]

# classification -> injection families to route to
FAMILY_ROUTES = {
    CLASS_STRICT_NUMERIC: ["sqli"],
    CLASS_LOOSE_STRING: ["sqli", "ssti", "xss", "crlf"],
    CLASS_CONTAINER_TYPED: ["nosql", "mass_assignment"],
}

# family -> fact key chains trigger on
FAMILY_FACTS = {
    "sqli": "has_sqli_param",
    "ssti": "has_ssti_param",
    "xss": "has_xss_param",
    "crlf": "has_crlf_param",
    "nosql": "has_nosql_param",
    "mass_assignment": "has_mass_assignment_param",
}

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_FILENAME_RE = re.compile(r"^[\w.\-]+\.[A-Za-z0-9]{1,6}$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def classify_value(value):
    """Infer the observed type of a single sample value."""
    if value is None:
        return "string"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    s = str(value).strip()
    if s == "":
        return "string"
    low = s.lower()
    if low in ("true", "false"):
        return "bool"
    if _is_int(s):
        return "int"
    if _is_float(s):
        return "float"
    if _EMAIL_RE.match(s):
        return "email"
    if _UUID_RE.match(s):
        return "uuid"
    if _JWT_RE.match(s) and s.count(".") == 2:
        return "jwt"
    if _URL_RE.match(s):
        return "url"
    if _FILENAME_RE.match(s) and "." in s:
        return "filename"
    if len(s) >= 8 and len(s) % 4 == 0 and _BASE64_RE.match(s) \
            and not s.isalpha():
        if _looks_base64(s):
            return "base64"
    return "string"


def _is_int(s):
    try:
        int(s)
        return True
    except (TypeError, ValueError):
        return False


def _is_float(s):
    try:
        float(s)
        return not _is_int(s)
    except (TypeError, ValueError):
        return False


def _looks_base64(s):
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


@dataclass
class ProbeResult:
    label: str
    kind: str
    value: Any
    status: Optional[int] = None
    accepted: bool = False
    signal_strength: float = 0.0
    notes: list = field(default_factory=list)
    error: Optional[str] = None

    def as_dict(self):
        return {
            "label": self.label,
            "kind": self.kind,
            "value": self.value,
            "status": self.status,
            "accepted": self.accepted,
            "signal_strength": round(self.signal_strength, 4),
            "notes": list(self.notes),
            "error": self.error,
        }


@dataclass
class ParamNode:
    name: str
    sources: list = field(default_factory=list)
    observed_types: list = field(default_factory=list)
    reflected: bool = False
    auth_contexts: list = field(default_factory=list)
    framework_param: bool = False
    probes: list = field(default_factory=list)
    mutation_candidates: list = field(default_factory=list)
    classification: str = CLASS_UNKNOWN
    arithmetic_injection: bool = False

    def add_source(self, src):
        if src and src not in self.sources:
            self.sources.append(src)

    def add_observed_type(self, t):
        if t and t not in self.observed_types:
            self.observed_types.append(t)

    def add_auth_context(self, ctx):
        if ctx and ctx not in self.auth_contexts:
            self.auth_contexts.append(ctx)

    def families(self):
        return injection_families_for(self)

    def as_dict(self):
        return {
            "name": self.name,
            "sources": list(self.sources),
            "observed_types": list(self.observed_types),
            "reflected": self.reflected,
            "auth_contexts": list(self.auth_contexts),
            "framework_param": self.framework_param,
            "probes": [p.as_dict() if isinstance(p, ProbeResult) else p
                       for p in self.probes],
            "mutation_candidates": list(self.mutation_candidates),
            "classification": self.classification,
            "arithmetic_injection": self.arithmetic_injection,
        }


def _accepted(status):
    return status is not None and 200 <= int(status) < 400


def run_type_probes(probe_runner, baseline=None, diff=None, marker=None):
    """Send the six canonical probes and return ProbeResult list.

    probe_runner(label, value) -> response dict with at least a "status";
    optionally "body", "headers", "content_type", "time_ms".
    """
    diff = diff or SemanticDiff()
    results = []
    for label, kind, qs_form, json_form in CANONICAL_PROBES:
        value = json_form
        try:
            resp = probe_runner(label, value)
        except Exception as e:  # network / runner failure
            results.append(ProbeResult(label=label, kind=kind, value=value,
                                       error=f"{type(e).__name__}: {e}"))
            continue
        if not isinstance(resp, dict):
            resp = {}
        status = resp.get("status")
        pr = ProbeResult(label=label, kind=kind, value=value,
                         status=status, accepted=_accepted(status))
        if baseline is not None:
            d = diff.compare(baseline, resp, marker=marker)
            pr.signal_strength = d.signal_strength
            pr.notes = list(d.notes)
            if d.marker_reflected:
                pr.notes.append("reflected")
        results.append(pr)
    return results


def classify_from_probes(probes):
    """Classify a param from its probe results.

    Returns one of strict_numeric / loose_string / container_typed /
    unknown.
    """
    by_label = {p.label: p for p in probes}
    int_ok = _label_accepted(by_label, "int")
    float_ok = _label_accepted(by_label, "float")
    string_ok = _label_accepted(by_label, "string")
    array_ok = _label_accepted(by_label, "array")
    object_ok = _label_accepted(by_label, "object")

    numeric_ok = int_ok and float_ok
    container_ok = array_ok or object_ok
    scalar_ok = int_ok or float_ok or string_ok

    if container_ok and not scalar_ok:
        return CLASS_CONTAINER_TYPED
    if numeric_ok and not string_ok:
        return CLASS_STRICT_NUMERIC
    if numeric_ok and string_ok:
        return CLASS_LOOSE_STRING
    if string_ok and not numeric_ok and not container_ok:
        return CLASS_LOOSE_STRING
    return CLASS_UNKNOWN


def _label_accepted(by_label, label):
    p = by_label.get(label)
    return bool(p and p.accepted)


def test_arithmetic_injection(arithmetic_runner, baseline=None, diff=None):
    """For strict_numeric params: send id=2-1 and compare to id=1.

    arithmetic_runner(value) -> response dict. Returns (candidate, evidence).
    The param is an arithmetic-injection candidate when 2-1 yields a
    response structurally equivalent to 1 (server evaluated the expression).
    """
    if arithmetic_runner is None:
        return False, {"reason": "no arithmetic runner"}
    diff = diff or SemanticDiff()
    try:
        resp_one = arithmetic_runner("1")
        resp_expr = arithmetic_runner("2-1")
    except Exception as e:
        return False, {"reason": f"{type(e).__name__}: {e}"}
    if not (_accepted((resp_expr or {}).get("status"))
            and _accepted((resp_one or {}).get("status"))):
        return False, {"reason": "2-1 not accepted"}
    snap = _snapshot_from_response(resp_one)
    d = diff.compare(snap, resp_expr)
    equivalent = (d.status_shift == 0.0 and d.structural_delta < 0.1
                  and d.length_delta_pct < 0.1)
    ev = {
        "one_status": resp_one.get("status"),
        "expr_status": resp_expr.get("status"),
        "structural_delta": round(d.structural_delta, 4),
        "length_delta_pct": round(d.length_delta_pct, 4),
    }
    return bool(equivalent), ev


def _snapshot_from_response(resp):
    body = (resp or {}).get("body") or ""
    ct = (resp or {}).get("content_type", "")
    return BaselineSnapshot(
        status=(resp or {}).get("status") or 0,
        body=body,
        body_len=len(body),
        structure=build_structure(body, ct),
        header_names=set(((resp or {}).get("headers") or {}).keys()),
    )


def infer_param_type(name, probe_runner, baseline=None, *,
                     sources=None, arithmetic_runner=None, diff=None,
                     marker=None, framework_param=False):
    """Run the oracle and return a classified ParamNode."""
    node = ParamNode(name=name, framework_param=bool(framework_param))
    for src in (sources or ["url"]):
        node.add_source(src)
    node.probes = run_type_probes(probe_runner, baseline=baseline,
                                  diff=diff, marker=marker)
    node.classification = classify_from_probes(node.probes)
    if any(p.notes and "reflected" in p.notes for p in node.probes):
        node.reflected = True
    for p in node.probes:
        if p.accepted and p.kind in ("numeric", "string"):
            node.add_observed_type("int" if p.label == "int"
                                   else "float" if p.label == "float"
                                   else "string")
    if node.classification == CLASS_STRICT_NUMERIC:
        candidate, ev = test_arithmetic_injection(
            arithmetic_runner, baseline=baseline, diff=diff)
        node.arithmetic_injection = candidate
        if candidate:
            node.mutation_candidates.append({"kind": "arithmetic_injection",
                                             "evidence": ev})
    node.mutation_candidates.extend(
        {"kind": "family", "family": fam}
        for fam in injection_families_for(node))
    return node


def injection_families_for(node):
    """Map a node's classification/observed types to injection families."""
    if isinstance(node, ParamNode):
        classification = node.classification
    elif isinstance(node, dict):
        classification = node.get("classification", CLASS_UNKNOWN)
    else:
        classification = CLASS_UNKNOWN
    return list(FAMILY_ROUTES.get(classification, []))


def fact_key(endpoint, name):
    return f"param:{endpoint}:{name}"


def record_param_node(fact_store, endpoint, node, source="route_probe",
                      confidence=0.7):
    """Store the node as a fact and emit family facts for chain triggers."""
    if fact_store is None:
        return []
    value = node.as_dict() if isinstance(node, ParamNode) else node
    fact_store.add(fact_key(endpoint, node.name if isinstance(node, ParamNode)
                            else node.get("name")),
                   value, source=source, confidence=confidence)
    emitted = []
    for fam in injection_families_for(node):
        fk = FAMILY_FACTS.get(fam)
        if not fk:
            continue
        fact_store.add(fk, True, source=source, confidence=confidence)
        emitted.append(fk)
    classification = (node.classification if isinstance(node, ParamNode)
                      else node.get("classification"))
    if classification == CLASS_STRICT_NUMERIC:
        fact_store.add("has_numeric_injection_param", True,
                       source=source, confidence=confidence)
    elif classification == CLASS_CONTAINER_TYPED:
        fact_store.add("has_container_param", True,
                       source=source, confidence=confidence)
    elif classification == CLASS_LOOSE_STRING:
        fact_store.add("has_loose_string_param", True,
                       source=source, confidence=confidence)
    return emitted


def make_http_probe_runner(client, url, param, method="GET",
                           location="query", headers=None):
    """Build a probe_runner over engine.http.Client (rate-limited, scoped).

    location: "query" sends the probe as a string query/body value;
    "json" sends the native typed JSON value in the request body.
    """
    headers = headers or {}

    def _resp(r):
        try:
            ct = r.headers.get("content-type", "")
        except Exception:
            ct = ""
        return {
            "status": r.status_code,
            "body": r.text or "",
            "headers": dict(getattr(r, "headers", {}) or {}),
            "content_type": ct,
        }

    def runner(label, value):
        if location == "json":
            r = client.request(method, url, json={param: value},
                               headers=headers)
            return _resp(r)
        qs_form = _query_form(value)
        if method.upper() in ("GET", "HEAD", "DELETE", "OPTIONS"):
            r = client.request(method, url, params={param: qs_form},
                               headers=headers)
        else:
            r = client.request(method, url, data={param: qs_form},
                               headers=headers)
        return _resp(r)

    return runner


def _query_form(value):
    if value is None:
        return "null"
    if isinstance(value, list):
        return "[]"
    if isinstance(value, dict):
        return "{}"
    return str(value)


__all__ = [
    "ParamNode", "ProbeResult", "SOURCES", "OBSERVED_TYPES", "AUTH_CONTEXTS",
    "CANONICAL_PROBES", "FAMILY_ROUTES", "FAMILY_FACTS",
    "CLASS_STRICT_NUMERIC", "CLASS_LOOSE_STRING", "CLASS_CONTAINER_TYPED",
    "CLASS_UNKNOWN", "classify_value", "run_type_probes",
    "classify_from_probes", "infer_param_type", "injection_families_for",
    "test_arithmetic_injection", "record_param_node", "fact_key",
    "make_http_probe_runner",
]
