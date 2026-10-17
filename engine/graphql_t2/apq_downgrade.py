"""Automatic Persisted Queries downgrade & weak hash detection."""
import hashlib
from .. import http as _http
from ..roe_guard import ROEGuard

def scan(endpoint, roe_guard=None):
    if roe_guard is None: roe_guard = ROEGuard()
    roe_guard.check_url(endpoint, "POST")

    query = "{ __typename }"
    sha256 = hashlib.sha256(query.encode()).hexdigest()

    # 1. Send hash only (should fail with PersistedQueryNotFound)
    with _http.Client(timeout=8, follow_redirects=False) as c:
        r1 = c.post(endpoint, json={"extensions": {"persistedQuery": {"version": 1, "sha256Hash": sha256}}})

    # 2. Send hash + query (should succeed and persist)
    with _http.Client(timeout=8, follow_redirects=False) as c:
        r2 = c.post(endpoint, json={"query": query, "extensions": {"persistedQuery": {"version": 1, "sha256Hash": sha256}}})

    # 3. Send hash only again (should succeed if APQ is active)
    with _http.Client(timeout=8, follow_redirects=False) as c:
        r3 = c.post(endpoint, json={"extensions": {"persistedQuery": {"version": 1, "sha256Hash": sha256}}})

    if r1.status_code == 200 and "PersistedQueryNotFound" in r1.text:
        if r3.status_code == 200 and "data" in r3.text:
            return {"verdict": "SUSPICIOUS", "reason": "APQ active, potential DoS/cache poisoning vector"}
    return {"verdict": "PASS", "reason": "APQ not active or properly secured"}
