"""3-level deep alias multiplication (<=27 nodes). Depth-limit proof only."""
from .. import http as _http
from ..roe_guard import ROEGuard

def scan(endpoint, roe_guard=None):
    if roe_guard is None: roe_guard = ROEGuard()
    roe_guard.check_url(endpoint, "POST")

    # 3 levels: 3x3x3 = 27 nodes
    query = "{ a1: node { b1: node { c1: node { id } } } }"

    with _http.Client(timeout=10, follow_redirects=False) as c:
        r = c.post(endpoint, json={"query": query}, headers={"Content-Type": "application/json"})

    if r.status_code == 200 and ("depth" in r.text.lower() or "complexity" in r.text.lower()):
        return {"verdict": "PASS", "reason": "Depth limit enforced"}
    if r.status_code == 200 and "data" in r.text:
        return {"verdict": "VULNERABLE", "reason": "3-level dataloader nesting accepted"}
    return {"verdict": "UNKNOWN", "reason": "Ambiguous response"}
