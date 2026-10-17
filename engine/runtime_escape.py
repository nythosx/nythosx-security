"""Gated runtime escape probe (read-only proofs)."""
from . import http as _http
from .roe_guard import ROEGuard, ROEViolation

def probe(url, allow_destructive=False, roe_guard=None):
    if not allow_destructive:
        return {"verdict": "UNKNOWN", "reason": "Destructive probes disabled (allow_destructive=False)"}
    if roe_guard is not None:
        try:
            roe_guard.check_url(url, "POST")
        except ROEViolation:
            return {"verdict": "UNKNOWN", "reason": "ROE_BLOCK"}

    payload = {"input": "{{7*7}}"}
    with _http.Client(timeout=8, follow_redirects=False) as c:
        r = c.post(url, json=payload, headers={"Connection": "close"})

    if "49" in r.text:
        return {"verdict": "VULNERABLE", "reason": "Runtime escape confirmed (SSTI echo 49)"}
    return {"verdict": "PASS", "reason": "No runtime escape"}
