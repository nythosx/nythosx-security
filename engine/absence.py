"""Absence testing — scanning the negative space.
Asserts that required security controls are MISSING.
"""
import time
import threading
from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http

def assert_no_rate_limit(url, method="POST", body=None, headers=None, count=10, timeout=8, roe_guard=None):
    """Fires `count` identical requests rapidly. If all succeed, rate limiting is absent."""
    if roe_guard:
        try: roe_guard.check_url(url, method)
        except ROEViolation: return {"verdict": "UNKNOWN", "reason": "ROE_BLOCK"}
        
    successes = 0
    lock = threading.Lock()
    
    def fire():
        nonlocal successes
        try:
            with _http.Client(timeout=timeout, verify=True, follow_redirects=False) as c:
                r = c.request(method, url, json=body, headers=headers or {}, skip_rate_limit=True)
                if 200 <= r.status_code < 300:
                    with lock: successes += 1
        except Exception:
            pass

    threads = [threading.Thread(target=fire) for _ in range(count)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=timeout + 2)
    
    if successes >= count * 0.9:
        return {"verdict": "VULNERABLE", "reason": f"No rate limit: {successes}/{count} succeeded", "evidence": {"successes": successes}}
    return {"verdict": "PASS", "reason": f"Rate limit enforced ({successes}/{count} succeeded)"}

def assert_no_idempotency(url, method="POST", body=None, headers=None, timeout=8, roe_guard=None):
    """Fires the same state-changing request twice. If both succeed, idempotency is missing."""
    if roe_guard:
        try: roe_guard.check_url(url, method)
        except ROEViolation: return {"verdict": "UNKNOWN", "reason": "ROE_BLOCK"}
        
    statuses = []
    for _ in range(2):
        try:
            with _http.Client(timeout=timeout, verify=True, follow_redirects=False) as c:
                r = c.request(method, url, json=body, headers=headers or {})
                statuses.append(r.status_code)
        except Exception:
            statuses.append(None)
        time.sleep(0.5)
        
    if all(200 <= s < 300 for s in statuses):
        return {"verdict": "VULNERABLE", "reason": "Missing idempotency: both requests succeeded", "evidence": {"statuses": statuses}}
    return {"verdict": "PASS", "reason": "Idempotency enforced or request failed"}
