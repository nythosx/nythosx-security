import threading
import time

import httpx
import pytest

from engine import webui, progress
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
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })


def test_new_ui_served_by_default(server):
    r = httpx.get(server + "/?ui=analyze", timeout=5)
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "transcript" in r.text
    assert "narrator" in r.text.lower()


def test_flow_ui_is_default(server):
    r = httpx.get(server + "/", timeout=5)
    assert r.status_code == 200
    assert 'id="chart"' in r.text
    assert 'id="flowUrl"' in r.text


def test_classic_ui_still_available(server):
    r = httpx.get(server + "/?ui=classic", timeout=5)
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "PAGE_CLASSIC" not in r.text
    assert "Pipeline flow" in r.text or "Analyze" in r.text


def test_new_ui_has_url_and_analyze(server):
    r = httpx.get(server + "/?ui=analyze", timeout=5)
    assert r.status_code == 200
    assert 'id="url"' in r.text
    assert "Analyze" in r.text


def test_stream_emits_narrator_events(server):
    job_id = "test-narrator-stream-001"
    progress.clear(job_id)

    progress.emit(job_id, "framework", {
        "id": "express", "name": "Express", "score": 9,
    })
    progress.emit(job_id, "done", {"counts": {}})

    r = httpx.get(server + f"/api/scan/{job_id}/stream", timeout=10)
    assert r.status_code == 200
    body = r.text

    assert "framework" in body
    assert "narrator" in body
    assert "Express" in body


def test_stream_narrator_for_phase(server):
    job_id = "test-narrator-stream-002"
    progress.clear(job_id)

    progress.emit(job_id, "phase", {
        "name": "preflight", "status": "running",
    })
    progress.emit(job_id, "done", {"counts": {}})

    r = httpx.get(server + f"/api/scan/{job_id}/stream", timeout=10)
    assert r.status_code == 200
    body = r.text

    assert "narrator" in body
    assert "responds" in body


def test_job_endpoint_returns_narrator_summary(server):
    job_id = "test-narrator-summary-001"
    progress.clear(job_id)

    webui._set(job_id, status="done", result={
        "target": "http://x",
        "counts": {"VULNERABLE": 1},
        "findings": [
            {"pattern_id": "env-file-exposure", "verdict": "VULNERABLE",
             "reason": "env leaked"},
        ],
        "chains": [],
    })

    r = httpx.get(server + f"/api/job/{job_id}", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert "narrator_summary" in data
    assert data["narrator_summary"]["target"] == "http://x"
    assert len(data["narrator_summary"]["bullets"]) >= 1
    assert data["narrator_summary"]["closing"]


def test_job_endpoint_omits_summary_when_not_done(server):
    job_id = "test-narrator-summary-002"
    progress.clear(job_id)

    webui._set(job_id, status="running")

    r = httpx.get(server + f"/api/job/{job_id}", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert "narrator_summary" not in data


def test_page_classic_constant_exists():
    from engine import webui
    assert hasattr(webui, "PAGE_CLASSIC")
    assert hasattr(webui, "PAGE")
    assert webui.PAGE != webui.PAGE_CLASSIC
