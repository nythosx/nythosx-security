import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _mock import MockHandler, serve_url  # noqa: E402

from engine import roe_guard as roe_mod  # noqa: E402
from engine.http_async import run_sync  # noqa: E402


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


def test_run_sync_in_sync_context():
    async def _coro():
        return 42
    assert run_sync(_coro()) == 42


def test_run_sync_from_running_loop():
    async def _outer():
        async def _inner():
            return 7
        return run_sync(_inner())
    assert asyncio.run(_outer()) == 7


class _BucketHandler(MockHandler):
    def handle_request(self, method, path, headers, body):
        if "publicbucket" in path:
            return (200, {"Content-Type": "application/xml"},
                    '<?xml version="1.0"?><ListBucketResult>'
                    '<Contents><Key>x</Key></Contents></ListBucketResult>')
        return (404, {"Content-Type": "application/xml"},
                '<Error><Code>NoSuchBucket</Code></Error>')


def test_cloud_storage_async_matches_sync():
    from engine import cloud_storage
    url, srv = serve_url(_BucketHandler)
    try:
        host = url.replace("http://", "")
        endpoints = [{"provider": "s3",
                      "url_template": f"http://{host}/{{bucket}}/"}]
        sync_result = cloud_storage.scan("publicbucket.com",
                                          endpoints=endpoints, max_buckets=1)
        async_result = run_sync(cloud_storage.scan_async(
            "publicbucket.com", endpoints=endpoints, max_buckets=1))
    finally:
        srv.shutdown(); srv.server_close()
    assert sync_result["verdict"] == async_result["verdict"] == "VULNERABLE"


class _PathHandler(MockHandler):
    def handle_request(self, method, path, headers, body):
        if path.startswith("/api/"):
            return (200, {"Content-Type": "application/json"}, '{"ok":true}')
        return (404, {"Content-Type": "text/html"}, "<html>nf</html>")


def test_discovery_probe_paths_async_matches_sync():
    from engine import discovery
    url, srv = serve_url(_PathHandler)
    try:
        sync_result = discovery.probe_paths(url, ["/api/a", "/api/b"],
                                             limit=5, timeout=5)
        async_result = run_sync(discovery.probe_paths_async(
            url, ["/api/a", "/api/b"], limit=5, timeout=5))
    finally:
        srv.shutdown(); srv.server_close()
    sync_verdicts = sorted(r["verdict"] for r in sync_result)
    async_verdicts = sorted(r["verdict"] for r in async_result)
    assert sync_verdicts == async_verdicts
    assert "live_api" in sync_verdicts


class _HerokuHandler(MockHandler):
    def handle_request(self, method, path, headers, body):
        return (404, {"Content-Type": "text/html"},
                "<html><body>Heroku | No such app</body></html>")


def test_subdomain_takeover_async_matches_sync():
    from engine import subdomain_takeover
    url, srv = serve_url(_HerokuHandler)
    try:
        sync_result = subdomain_takeover.scan([url])
        async_result = run_sync(subdomain_takeover.scan_async([url]))
    finally:
        srv.shutdown(); srv.server_close()
    assert sync_result["verdict"] == async_result["verdict"] == "VULNERABLE"


def test_subdomain_takeover_async_roe_block(monkeypatch):
    from engine import subdomain_takeover
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })
    result = run_sync(subdomain_takeover.scan_async(["http://127.0.0.1:1/"]))
    assert result["verdict"] == "UNKNOWN"
    assert "ROE_BLOCK" in result.reason


def test_api_discovery_port_scan_async_runs():
    from engine import api_discovery
    url, srv = serve_url(_PathHandler)
    try:
        host = url.replace("http://127.0.0.1:", "")
        port = int(host)
        result = run_sync(api_discovery.port_scan_async(
            f"http://127.0.0.1:{port}",
            ports=[port],
            timeout=3,
        ))
    finally:
        srv.shutdown(); srv.server_close()
    assert isinstance(result, list)
