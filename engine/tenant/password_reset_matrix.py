"""Password reset entropy and timing matrix."""
import re
import math
from .. import http as _http
from ..roe_guard import ROEGuard, ROEViolation

def probe_entropy(base_url, email, roe_guard=None, timeout=8):
    url = f"{base_url}/api/password/reset"
    if roe_guard is not None:
        try:
            roe_guard.check_url(url, "POST")
        except ROEViolation:
            return {"verdict": "UNKNOWN", "reason": "ROE_BLOCK"}

    tokens = []
    # Use Connection: close to prevent httpx keep-alive issues with simple http.server
    headers = {"Connection": "close"}
    with _http.Client(timeout=timeout, follow_redirects=False) as c:
        for _ in range(20):
            try:
                r = c.post(url, json={"email": email}, headers=headers)
                if r.status_code == 200 and "token" in r.text:
                    m = re.search(r'"token"\s*:\s*"([^"]+)"', r.text)
                    if m:
                        tokens.append(m.group(1))
            except Exception:
                pass

    if not tokens:
        return {"verdict": "PASS", "reason": "No tokens leaked in response"}

    unique_chars = set("".join(tokens))
    entropy = len(unique_chars) * math.log2(len(unique_chars)) if unique_chars else 0
    avg_len = sum(len(t) for t in tokens) / len(tokens)

    if entropy < 32 or avg_len < 8:
        return {"verdict": "SUSPICIOUS", "reason": f"Low entropy reset tokens (chars={len(unique_chars)}, len={avg_len:.1f})"}
    return {"verdict": "PASS", "reason": "Reset token entropy sufficient"}
