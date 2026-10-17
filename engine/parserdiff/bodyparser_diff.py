"""Body-parser confusion on the same origin.

Send the same semantic payload in multiple serializations and detect where
a front-end and back-end disagree on accepted fields, types, or content
types. Divergence in accepted-fields is a finding: a WAF may block
`"role":"admin"` in JSON while the PHP backend accepts `role=admin` in a
urlencoded body on the same route.
"""
from __future__ import annotations

import json
from urllib.parse import urlencode

from ..config import load_engine
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


SAMPLE_PAYLOAD = {"role": "admin", "is_admin": True, "username": "probe"}


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
            return "ROE guard unavailable (fail-closed): %s" % e
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def make_serializations(payload=None):
    """Return list of (label, content_type, body_bytes) for one payload.

    Covers: canonical JSON, duplicate-key JSON, unicode-escaped keys,
    JSON5-ish (unquoted keys, comments), XML against a JSON endpoint,
    form-urlencoded with bracket notation, multipart-like nested field,
    JSON with BOM.
    """
    if payload is None:
        payload = SAMPLE_PAYLOAD
    try:
        canonical = json.dumps(payload, separators=(",", ":"))
    except Exception:
        canonical = '{"role":"admin"}'
    out = []

    out.append(("json_canonical", "application/json",
                canonical.encode("utf-8")))

    dup_pairs = []
    for k, v in payload.items():
        dup_pairs.append(json.dumps(k) + ":" + json.dumps(v))
    if payload.get("role"):
        dup_pairs.append('"role":"user"')
    out.append(("json_duplicate_key", "application/json",
                ("{" + ",".join(dup_pairs) + "}").encode("utf-8")))

    escaped = canonical.replace('"role"', '"\\u0072ole"')
    out.append(("json_unicode_key", "application/json",
                escaped.encode("utf-8")))

    json5 = "{" + ",".join(
        k + ":" + json.dumps(v) for k, v in payload.items()) + "}"
    out.append(("json5_unquoted", "application/json",
                json5.encode("utf-8")))

    xml = "<root>" + "".join(
        "<%s>%s</%s>" % (k, v, k) for k, v in payload.items()) + "</root>"
    out.append(("xml_against_json", "application/xml",
                xml.encode("utf-8")))

    form_pairs = []
    for k, v in payload.items():
        if isinstance(v, bool):
            v = "true" if v else "false"
        form_pairs.append((k, str(v)))
    form_pairs.append(("role[]", "admin"))
    out.append(("form_bracket", "application/x-www-form-urlencoded",
                urlencode(form_pairs).encode("utf-8")))

    nested = urlencode([("object[field]", "value"), ("role", "admin")])
    out.append(("form_nested", "application/x-www-form-urlencoded",
                nested.encode("utf-8")))

    bom = b"\xef\xbb\xbf" + canonical.encode("utf-8")
    out.append(("json_bom", "application/json", bom))

    return out


def probe_serializations(url, payload=None, timeout=8, roe_guard=None,
                          verify=None):
    if verify is None:
        verify = _verify_tls()
    attempts = []
    for label, ct, body in make_serializations(payload):
        viol = _roe_block(roe_guard, url, "POST")
        if viol:
            return {"blocked": True, "error": "ROE_BLOCK: " + viol}
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.post(url, content=body,
                           headers={"Content-Type": ct})
            attempts.append({
                "label": label,
                "content_type": ct,
                "status": r.status_code,
                "body_len": len(r.text or ""),
                "preview": (r.text or "")[:300],
                "accepted": 200 <= r.status_code < 300,
            })
        except Exception as e:
            attempts.append({
                "label": label,
                "content_type": ct,
                "error": "%s: %s" % (type(e).__name__, e),
            })
    return {"attempts": attempts}


def analyze_divergence(attempts):
    accepted = [a["label"] for a in attempts
                if a.get("accepted") and not a.get("error")]
    rejected = [a["label"] for a in attempts
                if not a.get("accepted") and not a.get("error")]
    return {
        "accepted_serializations": accepted,
        "rejected_serializations": rejected,
        "divergence": bool(accepted and rejected),
    }


def detect_bodyparser_divergence(url, payload=None, timeout=8,
                                   roe_guard=None):
    result = probe_serializations(url, payload=payload,
                                    timeout=timeout, roe_guard=roe_guard)
    if result.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": result["error"],
                "evidence": {}}
    attempts = result["attempts"]
    live = [a for a in attempts if not a.get("error")]
    if not live:
        return {"verdict": "UNKNOWN",
                "reason": "no serializer probes completed",
                "evidence": {"attempts": attempts}}
    divergence = analyze_divergence(attempts)
    if divergence["divergence"]:
        return {
            "verdict": "VULNERABLE",
            "reason": ("body-parser divergence: accepted %s, rejected %s"
                       % (divergence["accepted_serializations"],
                          divergence["rejected_serializations"])),
            "evidence": {"attempts": attempts,
                         "divergence": divergence},
            "divergence": divergence,
        }
    if divergence["accepted_serializations"]:
        return {
            "verdict": "PASS",
            "reason": ("all accepted serializations agree on the same "
                       "semantic payload"),
            "evidence": {"attempts": attempts,
                         "divergence": divergence},
            "divergence": divergence,
        }
    return {
        "verdict": "PASS",
        "reason": "no serialization was accepted",
        "evidence": {"attempts": attempts,
                     "divergence": divergence},
        "divergence": divergence,
    }
