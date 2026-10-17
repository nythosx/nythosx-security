"""100 aliases of node(id:) in one request. Bounded to own-tenant IDs 1-100."""
import json
from .. import http as _http
from ..roe_guard import ROEGuard

def scan(endpoint, tenant_id, roe_guard=None):
    if roe_guard is None: roe_guard = ROEGuard()
    roe_guard.check_url(endpoint, "POST")

    aliases = ",".join([f'a{i}: node(id: "{tenant_id}_{i}") {{ id }}' for i in range(1, 101)])
    query = f"{{ {aliases} }}"

    with _http.Client(timeout=10, follow_redirects=False) as c:
        r = c.post(endpoint, json={"query": query}, headers={"Content-Type": "application/json"})

    data = r.json() if r.status_code == 200 else {}
    resolved = sum(1 for k in data.get("data", {}) if k.startswith("a"))
    if resolved >= 90:
        return {"verdict": "VULNERABLE", "reason": f"Batch alias bypass: {resolved}/100 resolved"}
    return {"verdict": "PASS", "reason": "Batch aliases rejected or rate-limited"}
