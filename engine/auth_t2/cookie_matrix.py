"""Duplicate cookie precedence matrix (first vs last wins)."""
from .. import http as _http
from ..roe_guard import ROEGuard

def scan(target_url, cookie_name, roe_guard=None):
    if roe_guard is None: roe_guard = ROEGuard()
    roe_guard.check_url(target_url, "GET")

    # Send duplicate cookies: first=user, last=admin
    headers = {"Cookie": f"{cookie_name}=user; {cookie_name}=admin"}
    with _http.Client(timeout=8, follow_redirects=False) as c:
        r = c.get(target_url, headers=headers)

    body = r.text.lower()
    if "admin" in body and "user" not in body:
        return {"verdict": "VULNERABLE", "reason": "Last-wins precedence allowed privilege escalation"}
    if "user" in body and "admin" not in body:
        return {"verdict": "PASS", "reason": "First-wins precedence enforced"}
    return {"verdict": "UNKNOWN", "reason": "Ambiguous cookie handling"}
