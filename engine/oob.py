"""Out-of-band interaction listener with external callback support.

Modes:
  - loopback (default): binds a ThreadingHTTPServer on 127.0.0.1 and
    records interactions locally. Only works when the target can reach
    the scanner's loopback (i.e. the target is on the same host).
  - external: no listener. Payloads point at the configured external
    callback URL (interactsh, Burp Collaborator, self-hosted). We cannot
    observe hits from here; callers must use the external service's UI
    or API. Verdicts that depend on a hit will be UNKNOWN.
"""
import threading
import time
import uuid
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Collector(BaseHTTPRequestHandler):
    def _record(self):
        token = self.path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
        interaction = {
            "token": token,
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "client": self.client_address[0],
            "time": time.time(),
        }
        self.server.oob._add(token, interaction)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    do_GET = _record
    do_POST = _record
    do_PUT = _record
    do_HEAD = _record

    def log_message(self, *a):
        pass


class OOBServer:
    def __init__(self, host="127.0.0.1", port=0, external_url=None):
        self._interactions = defaultdict(list)
        self._lock = threading.Lock()
        self._httpd = None
        self._thread = None
        self._external_url = external_url.rstrip("/") if external_url else None
        self.host = host
        self.port = port

    # -- lifecycle --------------------------------------------------------
    def start(self):
        if self._external_url:
            return self
        if self._httpd is None:
            self._httpd = ThreadingHTTPServer((self.host, self.port),
                                              _Collector)
            self._httpd.oob = self
            self.host, self.port = self._httpd.server_address
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._httpd.serve_forever, daemon=True)
            self._thread.start()
        return self

    def stop(self):
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
            self._thread = None

    def set_external_url(self, url):
        self._external_url = url.rstrip("/") if url else None

    @property
    def mode(self):
        return "external" if self._external_url else "loopback"

    @property
    def is_external(self):
        return bool(self._external_url)

    @property
    def base_url(self):
        if self._external_url:
            return self._external_url
        if self._httpd is None:
            return ""
        return f"http://{self.host}:{self.port}"

    # -- payload URLs -----------------------------------------------------
    def new_token(self):
        return uuid.uuid4().hex[:16]

    def payload_url(self, token=None):
        token = token or self.new_token()
        base = self.base_url
        if not base:
            return token, ""
        return token, f"{base}/{token}"

    # -- interaction bookkeeping (loopback only) --------------------------
    def _add(self, token, interaction):
        with self._lock:
            self._interactions[token].append(interaction)

    def interactions(self, token):
        with self._lock:
            return list(self._interactions.get(token, []))

    def hit_count(self, token):
        with self._lock:
            return len(self._interactions.get(token, []))

    def wait_for_hit(self, token, timeout=5.0, poll=0.1):
        if self._external_url:
            # We cannot observe the external service from here.
            return False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.hit_count(token) > 0:
                return True
            time.sleep(poll)
        return self.hit_count(token) > 0

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


__all__ = ["OOBServer"]
