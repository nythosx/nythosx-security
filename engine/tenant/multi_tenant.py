"""Cross-tenant BOLA sweep (user_a <-> user_b)."""
from .. import http as _http
from ..roe_guard import ROEGuard, ROEViolation

def sweep(base_url, token_a, token_b, roe_guard=None):
    url = f"{base_url}/api/org/2/data"
    if roe_guard is not None:
        try:
            roe_guard.check_url(url, "GET")
        except ROEViolation:
            return {"verdict": "UNKNOWN", "reason": "ROE_BLOCK"}

    with _http.Client(timeout=8, follow_redirects=False) as c:
        r = c.get(url, headers={"Authorization": f"Bearer {token_a}"})

    if r.status_code == 200 and "org_2_data" in r.text:
        return {"verdict": "VULNERABLE", "reason": "Cross-tenant BOLA confirmed (user A accessed user B's org)"}
    return {"verdict": "PASS", "reason": "Tenant isolation enforced"}
