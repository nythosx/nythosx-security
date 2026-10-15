import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import budget as _budget
from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *a):
        pass


@pytest.fixture
def echo_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_async_client_returns_response(permissive_roe, echo_server):
    _budget.configure(max_requests=100)
    from engine.http_async import AsyncClient

    async def go():
        async with AsyncClient(timeout=5) as c:
            return await c.get(echo_server + "/api/x")

    r = asyncio.run(go())
    assert r.status_code == 200
    assert json.loads(r.text)["path"] == "/api/x"


def test_async_client_budget(permissive_roe, echo_server):
    _budget.configure(max_requests=100)
    from engine.http_async import AsyncClient

    async def go():
        async with AsyncClient(timeout=5) as c:
            await c.get(echo_server + "/a")
            await c.get(echo_server + "/b")

    asyncio.run(go())
    assert _budget.snapshot()["requests"] == 2


def test_async_client_roe_block(permissive_roe):
    _budget.configure(max_requests=100)
    from engine.http_async import AsyncClient, ROEBlock

    async def go():
        async with AsyncClient(timeout=5) as c:
            await c.get("http://evil.example.com/secret")

    with pytest.raises(ROEBlock):
        asyncio.run(go())


def test_async_client_budget_exceeded(permissive_roe, echo_server):
    _budget.configure(max_requests=1)
    from engine.http_async import AsyncClient

    async def go():
        async with AsyncClient(timeout=5) as c:
            await c.get(echo_server + "/a")
            await c.get(echo_server + "/b")

    with pytest.raises(_budget.BudgetExceeded):
        asyncio.run(go())
    _budget.configure(max_requests=100)


def test_async_client_redirect_same_origin(permissive_roe):
    _budget.configure(max_requests=100)

    class _Redir(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "/target")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"arrived"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Redir)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        from engine.http_async import AsyncClient

        async def go():
            async with AsyncClient(timeout=5, follow_redirects=True) as c:
                return await c.get(f"http://127.0.0.1:{port}/redir")

        r = asyncio.run(go())
        assert r.status_code == 200
        assert r.text == "arrived"
    finally:
        srv.shutdown()
        srv.server_close()


def test_async_client_concurrent_requests(permissive_roe, echo_server):
    _budget.configure(max_requests=200)
    from engine.http_async import AsyncClient

    async def go():
        async with AsyncClient(timeout=5) as c:
            coros = [c.get(echo_server + f"/x{i}") for i in range(20)]
            return await asyncio.gather(*coros)

    results = asyncio.run(go())
    assert len(results) == 20
    assert all(r.status_code == 200 for r in results)
    assert _budget.snapshot()["requests"] == 20
