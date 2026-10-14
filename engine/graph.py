"""Attack-surface graph.

Builds a directed graph of {endpoint, parameter, response field} nodes and
infers attack hypotheses from the edges between them.

The hypothesis inference is the interesting part. Three classes:

  A. Field flow: if a public endpoint returns a field F (say user_id) and an
     authenticated endpoint accepts F as a parameter, then the pair is a BOLA
     candidate — the attacker can read F from A and pin it into B.

  B. Sibling resource: if two endpoints share the same path shape with a
     numeric id leaf (/api/orders/{id} and /api/invoices/{id}), then a
     sequential-id probe against one informs the other.

  C. Public sensitive field: if an unauthenticated 200 response contains a
     field whose name matches a known sensitive pattern (email, ssn, token,
     api_key, password), that is candidate data exposure.

Hypotheses feed back into the differential scanner (which runs the actual
cross-auth probes) and can be surfaced to the brain.
"""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlparse


SENSITIVE_FIELD_PATTERNS = [
    r"^email$", r"^e_?mail_?address$",
    r"^ssn$", r"^social_?security",
    r"^password", r"^passwd$", r"^pwd$",
    r"^token$", r"^access_?token$", r"^refresh_?token$", r"^api_?key$",
    r"^secret", r"^private_?key", r"^client_?secret",
    r"^phone", r"^mobile", r"^address$", r"^dob$", r"^birth",
    r"^credit_?card$", r"^card_?number$", r"^cvv$", r"^iban$",
    r"^balance$", r"^salary$",
    r"^role$", r"^is_?admin$", r"^permissions?$",
]

SENSITIVE_FIELD_RE = re.compile("|".join(SENSITIVE_FIELD_PATTERNS), re.I)


_ID_LEAF_RE = re.compile(r"/\{[a-zA-Z_]*id[a-zA-Z_]*\}$|/\d+$")
_PATH_PARAM_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class SurfaceGraph:
    def __init__(self):
        self.endpoints = {}
        self.parameters = defaultdict(lambda: {"accepted": set(), "returned": set()})
        self.edges = []
        self._edge_keys = set()

    def add_endpoint(self, url, method="GET", status_anon=None,
                     status_auth=None, request_fields=None, response_fields=None,
                     content_type=None):
        key = (method.upper(), url)
        self.endpoints[key] = {
            "url": url,
            "method": method.upper(),
            "status_anon": status_anon,
            "status_auth": status_auth,
            "request_fields": sorted(set(request_fields or [])),
            "response_fields": sorted(set(response_fields or [])),
            "content_type": content_type or "",
        }
        for f in (request_fields or []):
            self.parameters[f]["accepted"].add(url)
        for f in (response_fields or []):
            self.parameters[f]["returned"].add(url)

    def add_edge(self, from_url, to_url, edge_type, field):
        key = (from_url, to_url, edge_type, field)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append({
            "from": from_url, "to": to_url,
            "type": edge_type, "field": field,
        })

    def find_field_flow_edges(self):
        for field, refs in self.parameters.items():
            for ret_url in refs["returned"]:
                for acc_url in refs["accepted"]:
                    if ret_url == acc_url:
                        continue
                    ret_ep = self._lookup(ret_url)
                    acc_ep = self._lookup(acc_url)
                    if ret_ep is None or acc_ep is None:
                        continue
                    if ret_ep["status_anon"] == 200 and acc_ep["status_anon"] in (401, 403):
                        self.add_edge(ret_url, acc_url, "field_flow", field)

    def find_sibling_edges(self):
        groups = defaultdict(list)
        for key, ep in self.endpoints.items():
            url = ep["url"]
            if _ID_LEAF_RE.search(url):
                shape = _ID_LEAF_RE.sub("/{id}", url)
                groups[shape].append(ep)
        for shape, eps in groups.items():
            for i, a in enumerate(eps):
                for b in eps[i + 1:]:
                    self.add_edge(a["url"], b["url"], "sibling_resource", "{id}")
                    self.add_edge(b["url"], a["url"], "sibling_resource", "{id}")

    def find_public_sensitive_fields(self):
        for key, ep in self.endpoints.items():
            if ep["status_anon"] != 200:
                continue
            for f in ep["response_fields"]:
                if SENSITIVE_FIELD_RE.search(f):
                    self.add_edge("public", ep["url"], "public_sensitive_field", f)

    def build(self):
        self.find_field_flow_edges()
        self.find_sibling_edges()
        self.find_public_sensitive_fields()
        return self

    def _lookup(self, url):
        for (m, u), ep in self.endpoints.items():
            if u == url:
                return ep
        return None

    def hypotheses(self):
        out = []
        seen = set()
        for e in self.edges:
            t = e["type"]
            if t == "field_flow":
                key = ("bola", e["from"], e["to"], e["field"])
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "kind": "bola_field_flow",
                    "source": e["from"],
                    "sink": e["to"],
                    "field": e["field"],
                    "confidence": 0.55,
                    "reason": (f"public endpoint {e['from']} returns '{e['field']}' "
                               f"and authenticated endpoint {e['to']} accepts it "
                               f"— cross-auth test candidate"),
                })
            elif t == "sibling_resource":
                key = ("sib", e["from"], e["to"])
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "kind": "sibling_id_probe",
                    "source": e["from"],
                    "sink": e["to"],
                    "confidence": 0.4,
                    "reason": (f"sibling resource shapes: {e['from']} and "
                               f"{e['to']} both use numeric id leaf"),
                })
            elif t == "public_sensitive_field":
                key = ("pub", e["to"], e["field"])
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "kind": "public_sensitive_field",
                    "sink": e["to"],
                    "field": e["field"],
                    "confidence": 0.6,
                    "reason": (f"unauthenticated 200 from {e['to']} contains "
                               f"field '{e['field']}'"),
                })
        return out

    def stats(self):
        return {
            "endpoints": len(self.endpoints),
            "parameters": len(self.parameters),
            "edges": len(self.edges),
            "hypotheses": len(self.hypotheses()),
        }

    def to_dict(self):
        return {
            "endpoints": [
                {"method": m, "url": ep["url"],
                 "status_anon": ep["status_anon"], "status_auth": ep["status_auth"],
                 "request_fields": ep["request_fields"],
                 "response_fields": ep["response_fields"]}
                for (m, _), ep in self.endpoints.items()
            ],
            "edges": list(self.edges),
            "hypotheses": self.hypotheses(),
            "stats": self.stats(),
        }


def fields_from_json(obj, depth=0, max_depth=4, out=None):
    """Extract field names from a parsed JSON structure."""
    if out is None:
        out = set()
    if depth > max_depth:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k)
            fields_from_json(v, depth + 1, max_depth, out)
    elif isinstance(obj, list):
        for item in obj[:10]:
            fields_from_json(item, depth + 1, max_depth, out)
    return out


def fields_from_body(body, content_type=""):
    import json
    ct = (content_type or "").lower()
    if not body:
        return set()
    if "json" in ct or body.lstrip().startswith(("{", "[")):
        try:
            return fields_from_json(json.loads(body))
        except Exception:
            return set()
    return set()


__all__ = ["SurfaceGraph", "fields_from_json", "fields_from_body",
           "SENSITIVE_FIELD_RE"]
