import hmac
import json
import base64
import hashlib

from engine import oracle


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_jwt(secret, alg="HS256", payload=None):
    algs = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    header = _b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload or {"sub": "1", "admin": True}).encode())
    signing_input = f"{header}.{body}".encode()
    sig = _b64url(hmac.new(secret.encode(), signing_input, algs[alg]).digest())
    return f"{header}.{body}.{sig}"


def _ctx_with_body(body):
    return {"steps": [{"step_name": "probe", "body": body, "headers": {}}],
            "inputs": {}, "target": "http://t"}


def test_detects_weak_secret_in_body():
    token = _make_jwt("secret")
    ctx = _ctx_with_body(json.dumps({"token": token}))
    r = oracle.evaluate({"type": "jwt_weak_secret"}, ctx)
    assert r["verdict"] == "VULNERABLE"
    assert r["evidence"]["secret"] == "secret"
    assert r["evidence"]["alg"] == "HS256"


def test_strong_secret_passes():
    token = _make_jwt("Z9f!x2Q^v8M#p1L&w7R$t4Y*correct-horse-battery")
    ctx = _ctx_with_body(json.dumps({"token": token}))
    r = oracle.evaluate({"type": "jwt_weak_secret"}, ctx)
    assert r["verdict"] == "PASS"


def test_no_jwt_is_unknown():
    r = oracle.evaluate({"type": "jwt_weak_secret"},
                        _ctx_with_body('{"message": "ok"}'))
    assert r["verdict"] == "UNKNOWN"


def test_hs512_weak_secret():
    token = _make_jwt("changeme", alg="HS512")
    ctx = _ctx_with_body(token)
    r = oracle.evaluate({"type": "jwt_weak_secret"}, ctx)
    assert r["verdict"] == "VULNERABLE"
    assert r["evidence"]["alg"] == "HS512"


def test_inline_secret_list_override():
    token = _make_jwt("hunter2")
    ctx = _ctx_with_body(token)
    r = oracle.evaluate({"type": "jwt_weak_secret", "secrets": ["hunter2"]}, ctx)
    assert r["verdict"] == "VULNERABLE"
    assert r["evidence"]["secret"] == "hunter2"


def test_token_in_authorization_header():
    token = _make_jwt("admin")
    ctx = {"steps": [{"step_name": "probe", "body": "",
                      "headers": {"Authorization": f"Bearer {token}"}}],
           "inputs": {}, "target": "http://t"}
    r = oracle.evaluate({"type": "jwt_weak_secret"}, ctx)
    assert r["verdict"] == "VULNERABLE"


def test_non_hmac_token_not_crackable():
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps({"sub": "1"}).encode())
    token = f"{header}.{body}.{_b64url(b'fakesig-not-hmac')}"
    ctx = _ctx_with_body(token)
    r = oracle.evaluate({"type": "jwt_weak_secret"}, ctx)
    assert r["verdict"] == "UNKNOWN"
    assert "HMAC" in r["reason"]
