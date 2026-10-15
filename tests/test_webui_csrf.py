import threading

import httpx
import pytest

from engine import webui
from engine import roe_guard as roe_mod


@pytest.fixture
def server():
    httpd = webui.serve(port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    _, port = httpd.server_address
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


def test_csrf_endpoint_returns_token(server):
    r = httpx.get(server + "/api/csrf", timeout=5)
    assert r.status_code == 200
    body = r.json()
    assert "token" in body
    assert len(body["token"]) > 20


def test_post_without_csrf_rejected(server):
    r = httpx.post(server + "/api/scan", json={"url": "http://127.0.0.1:1"},
                    timeout=5)
    assert r.status_code == 403
    assert "CSRF" in r.json().get("error", "")


def test_post_with_wrong_csrf_rejected(server):
    r = httpx.post(server + "/api/scan", json={"url": "http://127.0.0.1:1"},
                    headers={"X-CSRF-Token": "wrong"},
                    timeout=5)
    assert r.status_code == 403
    assert "CSRF" in r.json().get("error", "")


def test_post_with_correct_csrf_passes_csrf_gate(server):
    token = httpx.get(server + "/api/csrf", timeout=5).json()["token"]
    r = httpx.post(server + "/api/scan", json={"url": "http://evil.example.com"},
                    headers={"X-CSRF-Token": token}, timeout=5)
    assert r.status_code == 403
    body = r.json()
    assert "ROE" in body.get("error", "") or "scope" in body.get("error", "").lower()
    assert "CSRF" not in body.get("error", "")


def test_get_requests_do_not_require_csrf(server):
    r = httpx.get(server + "/", timeout=5)
    assert r.status_code == 200
