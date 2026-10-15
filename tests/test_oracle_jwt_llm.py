import base64
import hashlib
import hmac
import json

from engine import oracle, llm_service


def _make_jwt(secret, alg="HS256"):
    def _b(d):
        return base64.urlsafe_b64encode(
            json.dumps(d).encode()).rstrip(b"=").decode()
    head = _b({"alg": alg, "typ": "JWT"})
    pay = _b({"user": "a", "role": "user"})
    signing = f"{head}.{pay}".encode()
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), signing, hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{head}.{pay}.{sig}"


def _ctx(token):
    return {"target": "https://acme.example.com",
            "framework": "laravel",
            "steps": [{"step_name": "login", "body": token, "headers": {}}]}


def test_jwt_no_ai_uses_wordlist_only(monkeypatch):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    assert oracle._llm_jwt_candidates(_ctx("x.y.z"), "x.y.z") == []
    token = _make_jwt("secret")
    oc = {"verdict": "VULNERABLE"}
    r = oracle._jwt_weak_secret(oc, _ctx(token))
    assert r["verdict"] == "VULNERABLE"
    assert r["evidence"]["secret"] == "secret"


def test_jwt_ai_candidates_prepended(monkeypatch):
    target_secret = "acme-prod-jwt-2024"
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: (
            lambda prompt: json.dumps([target_secret, "changeme"])))
    token = _make_jwt(target_secret)
    r = oracle._jwt_weak_secret({"verdict": "VULNERABLE"}, _ctx(token))
    assert r["verdict"] == "VULNERABLE"
    assert r["evidence"]["secret"] == target_secret


def test_jwt_ai_failure_falls_back(monkeypatch):
    def _boom(prompt):
        raise RuntimeError("llm down")
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: _boom)
    token = _make_jwt("secret")
    r = oracle._jwt_weak_secret({"verdict": "VULNERABLE"}, _ctx(token))
    assert r["evidence"]["secret"] == "secret"
