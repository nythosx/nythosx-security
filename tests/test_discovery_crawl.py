import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import discovery

_BUNDLES = {
    "/_nuxt/entry.js": b'const a=$fetch("/api/users");import("/_nuxt/lazy.js");'
                       b'const x="/_nuxt/second.js";',
    "/_nuxt/lazy.js": b'useFetch("/api/secret");var n="https://evil.cdn.com/tracker.js";',
    "/_nuxt/second.js": b'axios.get("/api/admin/stats");',
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = _BUNDLES.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def js_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_extract_chunk_urls_same_host_only():
    root = "http://127.0.0.1:3000"
    js = 'import("/_nuxt/a.js");var x="b.js";var e="https://cdn.evil.com/x.js";'
    refs = discovery.extract_chunk_urls(js, "http://127.0.0.1:3000/_nuxt/entry.js", root)
    assert "http://127.0.0.1:3000/_nuxt/a.js" in refs
    assert "http://127.0.0.1:3000/_nuxt/b.js" in refs
    assert not any("evil" in r for r in refs)


def test_recursive_crawl_follows_lazy_chunks(js_server):
    entry = f"{js_server}/_nuxt/entry.js"
    paths, fetched = discovery.crawl_js_for_paths(js_server, [entry], {})
    fetched_urls = {f["url"] for f in fetched}
    assert f"{js_server}/_nuxt/lazy.js" in fetched_urls
    assert f"{js_server}/_nuxt/second.js" in fetched_urls
    assert "/api/users" in paths
    assert "/api/secret" in paths
    assert "/api/admin/stats" in paths


def test_non_recursive_stays_shallow(js_server):
    entry = f"{js_server}/_nuxt/entry.js"
    paths, fetched = discovery.crawl_js_for_paths(
        js_server, [entry], {}, recursive=False)
    assert len(fetched) == 1
    assert "/api/users" in paths
    assert "/api/secret" not in paths


def test_crawl_respects_max_bundles(js_server):
    entry = f"{js_server}/_nuxt/entry.js"
    paths, fetched = discovery.crawl_js_for_paths(
        js_server, [entry], {}, max_bundles=1)
    assert len(fetched) == 1
