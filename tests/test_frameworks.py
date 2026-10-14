import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


class _LaravelVuln(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/_ignition/health-check":
                (200, b'{"can_execute_commands":true}'),
            "/_debugbar/open":
                (200, b'{"__meta":{"id":"x"}}'),
            "/telescope":
                (200, b'<html>Telescope</html>'),
            "/storage/logs/laravel.log":
                (200, b"[stack trace] production.ERROR foo"),
        }
        if self.path in routes:
            status, body = routes[self.path]
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class _SpringVuln(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/actuator": (200, b'{"_links":{"self":{}}}'),
            "/actuator/env":
                (200, b'{"propertySources":[{"name":"app","properties":{}}]}'),
            "/actuator/heapdump": (200, b"JAVA PROFILE 1.0.1"),
            "/actuator/gateway/routes":
                (200, b'[{"route_id":"r1","predicate":"Path=/x"}]'),
            "/actuator/loggers":
                (200, b'{"loggers":{"ROOT":{}}}'),
        }
        if self.path in routes:
            status, body = routes[self.path]
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class _WordPressVuln(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/wp-json/wp/v2/users":
                (200, b'[{"slug":"admin","name":"Admin"}]'),
            "/xmlrpc.php":
                (405, b"XML-RPC server accepts POST requests only."),
            "/wp-admin/setup-config.php":
                (200, b'<html>setup-config.php</html>'),
        }
        if self.path in routes:
            status, body = routes[self.path]
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if self.path == "/xmlrpc.php":
            body = b"<methodResponse><params><param><value>" \
                   b"<array><data><value>system.multicall</value>" \
                   b"<value>wp.getUsersBlogs</value></data></array>" \
                   b"</value></param></params></methodResponse>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class _GenericVuln(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/.git/config":
                (200, b"[core]\nrepositoryformatversion = 0\n"),
            "/server-status":
                (200, b"<html>Apache Server Status for x\nCurrent Time: ..."),
            "/Dockerfile":
                (200, b"FROM node:18\nCOPY . .\n"),
        }
        if self.path in routes:
            status, body = routes[self.path]
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class _CleanServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_laravel_probes_detect():
    from engine.frameworks import laravel
    srv = _serve(_LaravelVuln)
    _, port = srv.server_address
    try:
        r = laravel.scan(f"http://127.0.0.1:{port}")
    finally:
        srv.shutdown()
        srv.server_close()
    names = {f["probe"] for f in r["findings"]}
    assert "laravel_ignition_health_check" in names
    assert "laravel_debugbar_open" in names
    assert "laravel_log_exposure" in names


def test_spring_probes_detect():
    from engine.frameworks import spring_boot
    srv = _serve(_SpringVuln)
    _, port = srv.server_address
    try:
        r = spring_boot.scan(f"http://127.0.0.1:{port}")
    finally:
        srv.shutdown()
        srv.server_close()
    names = {f["probe"] for f in r["findings"]}
    assert "actuator_env" in names
    assert "actuator_gateway_routes" in names
    assert "actuator_heapdump" in names


def test_wordpress_probes_detect():
    from engine.frameworks import wordpress
    srv = _serve(_WordPressVuln)
    _, port = srv.server_address
    try:
        r = wordpress.scan(f"http://127.0.0.1:{port}")
    finally:
        srv.shutdown()
        srv.server_close()
    names = {f["probe"] for f in r["findings"]}
    assert "wp_users_enumeration" in names
    assert "wp_xmlrpc_reachable" in names
    assert "wp_xmlrpc_listmethods" in names


def test_generic_server_detect():
    from engine.frameworks import generic_server
    srv = _serve(_GenericVuln)
    _, port = srv.server_address
    try:
        r = generic_server.scan(f"http://127.0.0.1:{port}")
    finally:
        srv.shutdown()
        srv.server_close()
    names = {f["probe"] for f in r["findings"]}
    assert "git_config_exposure" in names
    assert "apache_server_status" in names
    assert "dockerfile_exposure" in names


def test_clean_target_no_findings():
    from engine.frameworks import scan_all
    srv = _serve(_CleanServer)
    _, port = srv.server_address
    try:
        r = scan_all(f"http://127.0.0.1:{port}", adapter_id="laravel")
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["findings"] == []


def test_scan_all_runs_expected_modules():
    from engine.frameworks import scan_all
    srv = _serve(_CleanServer)
    _, port = srv.server_address
    try:
        r = scan_all(f"http://127.0.0.1:{port}", adapter_id="laravel")
    finally:
        srv.shutdown()
        srv.server_close()
    mods = set(r["modules_run"])
    assert "laravel" in mods
    assert "generic_server" in mods
    assert "wordpress" in mods


def test_roe_block_reports_error(monkeypatch):
    from engine.frameworks import laravel
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })
    r = laravel.scan("http://127.0.0.1:1")
    assert r["findings"] == []
    assert any("ROE" in (p.get("error") or "") for p in r["probes"])
