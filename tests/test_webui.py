import json
import time
import threading

import httpx
import pytest

from engine import webui
from engine import auto as auto_mod
from engine import ledger
from engine import roe_guard as roe_mod


@pytest.fixture
def server():
    httpd = webui.serve(port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, port = httpd.server_address
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1", "localhost"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


def _csrf_post(server, path, **kwargs):
    token = httpx.get(server + "/api/csrf", timeout=5).json()["token"]
    headers = dict(kwargs.pop("headers", {}) or {})
    headers["X-CSRF-Token"] = token
    return httpx.post(server + path, headers=headers, **kwargs)


def test_index_serves_html(server):
    r = httpx.get(server + "/", timeout=5)
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert 'id="flowUrl"' in r.text
    assert 'id="goBtn"' in r.text


def test_analyze_ui_still_available(server):
    r = httpx.get(server + "/?ui=analyze", timeout=5)
    assert r.status_code == 200
    assert 'id="url"' in r.text
    assert "Analyze" in r.text


def test_scan_requires_url(server):
    r = _csrf_post(server, "/api/scan", json={}, timeout=5)
    assert r.status_code == 400


def test_scan_rejects_out_of_scope(server, monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })
    r = _csrf_post(server, "/api/scan", json={"url": "http://example.com"}, timeout=5)
    assert r.status_code == 403
    body = r.json()
    assert body["error"] == "URL not in ROE scope"
    assert "roe.yaml" in body["hint"]


def test_build_result_shapes_output(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    target = "http://127.0.0.1:8000/api"
    ledger.record_finding("cors-wildcard", target, "VULNERABLE", "high",
                          "cors *", "", {}, category="single")
    outcome = {"targets": {"api_base": target},
               "framework": {"adapter": {"name": "Laravel", "id": "laravel"},
                             "score": 80},
               "api_paths": ["/api/a", "/api/b"],
               "login": {"token": "x"},
               "counts": {"VULNERABLE": 1, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0},
               "report": "reports/x.html"}
    res = webui._build_result("http://127.0.0.1:8000", outcome, "log text")
    assert res["framework"]["name"] == "Laravel"
    assert res["api_base"] == target
    assert res["api_paths_count"] == 2
    assert res["logged_in"] is True
    assert len(res["findings"]) == 1
    assert res["findings"][0]["pattern_id"] == "cors-wildcard"
    assert res["log"] == "log text"


def test_full_job_flow(server, tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    target = "http://127.0.0.1:3000"

    def fake_run_auto(url, **kw):
        ledger.record_finding("security-headers-missing", url, "VULNERABLE",
                              "medium", "missing HSTS", "", {}, category="single")
        return {"targets": {"api_base": url},
                "framework": {"adapter": {"name": "Nuxt", "id": "nuxt"}, "score": 70},
                "api_paths": [], "login": None,
                "counts": {"VULNERABLE": 1, "SUSPICIOUS": 0, "PASS": 3, "UNKNOWN": 0},
                "report": "reports/r.html"}

    monkeypatch.setattr(auto_mod, "run_auto", fake_run_auto)

    r = _csrf_post(server, "/api/scan", json={"url": target}, timeout=5)
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    result = None
    for _ in range(50):
        jr = httpx.get(server + f"/api/job/{job_id}", timeout=5).json()
        if jr["status"] == "done":
            result = jr["result"]
            break
        if jr["status"] == "error":
            pytest.fail(f"job errored: {jr.get('error')}")
        time.sleep(0.1)
    assert result is not None, "job did not complete"
    assert result["framework"]["name"] == "Nuxt"
    assert result["counts"]["VULNERABLE"] == 1
    assert any(f["pattern_id"] == "security-headers-missing" for f in result["findings"])


def test_unknown_job_404(server):
    r = httpx.get(server + "/api/job/nope", timeout=5)
    assert r.status_code == 404
