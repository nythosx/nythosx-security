"""A2 — Parser-differential probes.

Re-send an accepted payload with a mismatched Content-Type. When the server
answers divergently, a front layer (WAF, router) and the app disagree on how
to parse the body — a classic bypass primitive. Bounded to 4 variants per
endpoint. No resource-exhaustion patterns.
"""
from __future__ import annotations

from urllib.parse import urlencode

from ..diff import BaselineSnapshot, SemanticDiff, build_structure

MAX_VARIANTS = 4


def _snapshot(resp):
    body = (resp or {}).get("body") or ""
    return BaselineSnapshot(
        status=(resp or {}).get("status") or 0, body=body, body_len=len(body),
        structure=build_structure(body, (resp or {}).get("content_type", "")),
        header_names=set(((resp or {}).get("headers") or {}).keys()))


def _json_as_form(json_body):
    if isinstance(json_body, dict):
        return urlencode({k: (v if isinstance(v, (str, int, float)) else str(v))
                          for k, v in json_body.items()})
    return str(json_body)


def build_variants(accepted_payload, content_type="application/json"):
    """Return up to MAX_VARIANTS (label, body, content_type, extra) tuples."""
    variants = []
    ct = (content_type or "").lower()
    if "json" in ct or isinstance(accepted_payload, dict):
        variants.append((
            "json_as_form", _json_as_form(accepted_payload),
            "application/x-www-form-urlencoded", {}))
    if "xml" in ct or (isinstance(accepted_payload, str)
                       and accepted_payload.lstrip().startswith("<")):
        variants.append(("xml_text", accepted_payload, "text/xml", {}))
        variants.append(("xml_app", accepted_payload, "application/xml", {}))
    # multipart with two 'file' parts sharing a filename
    variants.append((
        "multipart_dup_filename", None, None,
        {"files": [("file", ("a.txt", "one")),
                   ("file", ("a.txt", "two"))]}))
    return variants[:MAX_VARIANTS]


def scan(url, accepted_payload, send, method="POST",
         content_type="application/json", diff=None):
    """send(method, url, body, content_type, extra) -> response dict.

    `extra` may carry {"files": [...]} for multipart variants.
    """
    diff = diff or SemanticDiff()
    try:
        baseline = send(method, url, accepted_payload, content_type, {})
    except Exception as e:
        return {"verdict": "UNKNOWN", "reason": f"baseline failed: {e}",
                "evidence": {}, "findings": []}
    snap = _snapshot(baseline)
    findings = []
    for label, body, ct, extra in build_variants(accepted_payload,
                                                  content_type):
        try:
            resp = send(method, url, body, ct, extra)
        except Exception as e:
            findings.append({"variant": label, "verdict": "UNKNOWN",
                             "reason": str(e)})
            continue
        d = diff.compare(snap, resp)
        diverged = (d.status_shift > 0 or d.structural_delta > 0.2
                    or d.length_delta_pct > 0.5)
        findings.append({
            "variant": label,
            "verdict": "SUSPICIOUS" if diverged else "PASS",
            "severity": "medium" if diverged else "info",
            "reason": ("response diverged under mismatched Content-Type "
                       "(parser/WAF bypass candidate)" if diverged
                       else "no divergence"),
            "status": (resp or {}).get("status"),
            "signal_strength": d.signal_strength,
        })
    diverged_n = sum(1 for f in findings if f.get("verdict") == "SUSPICIOUS")
    return {
        "verdict": "SUSPICIOUS" if diverged_n else "PASS",
        "reason": f"{diverged_n}/{len(findings)} content-type variant(s) "
                  f"diverged",
        "evidence": {"variants": findings},
        "findings": findings,
    }


__all__ = ["build_variants", "scan", "MAX_VARIANTS"]
