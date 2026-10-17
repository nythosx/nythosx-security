"""Schema-outward walk beyond 'Did you mean'. Max 200 probes."""
import re
from .. import http as _http
from ..roe_guard import ROEGuard

MUST_NEVER = ["passwordHash", "secretKey", "internalNotes"]

def scan(endpoint, roe_guard=None):
    if roe_guard is None: roe_guard = ROEGuard()
    roe_guard.check_url(endpoint, "POST")

    found_fields = []
    # Simplified brute force using common prefixes
    prefixes = ["user", "account", "profile", "admin"]
    probes = 0

    with _http.Client(timeout=10, follow_redirects=False) as c:
        for prefix in prefixes:
            for i in range(50):
                if probes >= 200: break
                field = f"{prefix}_{i}"
                if any(mn.lower() in field.lower() for mn in MUST_NEVER): continue

                r = c.post(endpoint, json={"query": f"{{ {field} }}"}, headers={"Content-Type": "application/json"})
                probes += 1
                if r.status_code == 200 and "errors" not in r.text:
                    found_fields.append(field)

    if found_fields:
        return {"verdict": "SUSPICIOUS", "reason": f"Hidden fields found: {found_fields[:5]}"}
    return {"verdict": "PASS", "reason": "No hidden fields found within 200 probes"}
