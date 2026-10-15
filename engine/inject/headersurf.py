"""A4 — Header-surface injection.

Replays each discovered endpoint with mutated routing/trust headers that
host-based allowlists (common on .edu.ph hosting) mistakenly trust. A status
or structural shift versus the clean baseline flags an access-control or
routing bypass. GET-only replays; every request routes through engine.http.
"""
from __future__ import annotations

from ..diff import BaselineSnapshot, SemanticDiff, build_structure

TRUST_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-HTTP-Method-Override": "PUT"},
    {"X-Forwarded-Host": "localhost"},
]


def _snapshot(resp):
    body = (resp or {}).get("body") or ""
    return BaselineSnapshot(
        status=(resp or {}).get("status") or 0, body=body, body_len=len(body),
        structure=build_structure(body, (resp or {}).get("content_type", "")),
        header_names=set(((resp or {}).get("headers") or {}).keys()))


def _bypassed(baseline, resp, d):
    b_status = (baseline or {}).get("status")
    r_status = (resp or {}).get("status")
    # A forbidden/unauthorized baseline turning allowed is the strongest tell.
    if b_status in (401, 403, 404) and r_status is not None \
            and 200 <= int(r_status) < 300:
        return True, "forbidden baseline became reachable"
    if d.structural_delta > 0.3 or d.length_delta_pct > 0.6:
        return True, "response body diverged under trust header"
    return False, ""


def scan(url, send, baseline_resp=None, headers_list=None, diff=None):
    """send(method, url, headers) -> response dict. Returns per-header findings."""
    diff = diff or SemanticDiff()
    if baseline_resp is None:
        try:
            baseline_resp = send("GET", url, {})
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"baseline failed: {e}",
                    "evidence": {}, "findings": []}
    snap = _snapshot(baseline_resp)
    findings = []
    for hdr in (headers_list or TRUST_HEADERS):
        try:
            resp = send("GET", url, hdr)
        except Exception as e:
            findings.append({"header": hdr, "verdict": "UNKNOWN",
                             "reason": str(e)})
            continue
        d = diff.compare(snap, resp)
        bypassed, why = _bypassed(baseline_resp, resp, d)
        findings.append({
            "header": hdr,
            "verdict": "SUSPICIOUS" if bypassed else "PASS",
            "severity": "high" if bypassed else "info",
            "reason": why or "no bypass",
            "status": (resp or {}).get("status"),
            "signal_strength": d.signal_strength,
        })
    hits = [f for f in findings if f.get("verdict") == "SUSPICIOUS"]
    return {
        "verdict": "SUSPICIOUS" if hits else "PASS",
        "reason": f"{len(hits)}/{len(findings)} trust-header bypass candidate(s)",
        "evidence": {"headers": findings, "url": url},
        "findings": hits,
    }


__all__ = ["TRUST_HEADERS", "scan"]
