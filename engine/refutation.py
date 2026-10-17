"""Refutation-First Reporting.
Generates adversarial test cases to disprove a finding before it is emitted.
If a finding cannot survive its own adversarial review, it is downgraded.
"""
from . import http as _http
from .config import load_engine
from .roe_guard import ROEGuard

def refute_idor(url, token, roe_guard=None):
    """Try the IDOR endpoint without authentication. If it fails, the finding is real."""
    if not url:
        return {"refuted": False, "reason": "no url"}
    try:
        with _http.Client(timeout=8, verify=True, follow_redirects=False) as c:
            r = c.get(url)
            if r.status_code in (401, 403):
                return {"refuted": False, "reason": "unauth correctly rejected"}
            if r.status_code == 200:
                return {"refuted": True, "reason": "unauth succeeded - missing auth entirely"}
    except Exception as e:
        return {"refuted": False, "reason": f"error: {e}"}
    return {"refuted": False, "reason": "inconclusive"}

def refute_bola(url, token_a, token_b, roe_guard=None):
    """Try the BOLA endpoint with User A's token. If it succeeds, it's not BOLA, just normal access."""
    if not url or not token_a:
        return {"refuted": False, "reason": "missing params"}
    try:
        with _http.Client(timeout=8, verify=True, follow_redirects=False) as c:
            r = c.get(url, headers={"Authorization": f"Bearer {token_a}"})
            if r.status_code in (401, 403):
                return {"refuted": False, "reason": "user A correctly rejected"}
            if r.status_code == 200:
                return {"refuted": True, "reason": "user A can access it - not BOLA"}
    except Exception as e:
        return {"refuted": False, "reason": f"error: {e}"}
    return {"refuted": False, "reason": "inconclusive"}

def run_refutation(finding_type, url, context):
    if finding_type in ("idor", "bola"):
        return refute_idor(url, context.get("token"), context.get("roe_guard"))
    return {"refuted": False, "reason": "no refutation logic for type"}
