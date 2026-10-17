"""Mass-assignment at the front door (signup)."""
from .. import http as _http
from ..roe_guard import ROEGuard, ROEViolation

def probe_signup(base_url, roe_guard=None):
    url = f"{base_url}/api/register"
    if roe_guard is not None:
        try:
            roe_guard.check_url(url, "POST")
        except ROEViolation:
            return {"verdict": "UNKNOWN", "reason": "ROE_BLOCK"}

    payload = {"email": "attacker@test.com", "password": "Pass123!", "role": "admin"}
    with _http.Client(timeout=8, follow_redirects=False) as c:
        r = c.post(url, json=payload, headers={"Connection": "close"})

    body_clean = r.text.replace(" ", "").replace("\n", "")
    if r.status_code in (200, 201) and '"role":"admin"' in body_clean:
        return {"verdict": "VULNERABLE", "reason": "Mass-assignment: role=admin accepted at signup"}
    return {"verdict": "PASS", "reason": "Signup role field rejected or ignored"}
