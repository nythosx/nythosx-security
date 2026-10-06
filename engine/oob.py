import time
import uuid
import threading
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
    def __init__(self, host="127.0.0.1", port=0):
        self._interactions = defaultdict(list)
        self._lock = threading.Lock()
        self._httpd = ThreadingHTTPServer((host, port), _Collector)
        self._httpd.oob = self
        self.host, self.port = self._httpd.server_address
        self._thread = None

    def _add(self, token, interaction):
        with self._lock:
            self._interactions[token].append(interaction)

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._httpd.serve_forever,
                                            daemon=True)
            self._thread.start()
        return self

    def stop(self):
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception:
            pass

    @property
    def base_url(self):
        return f"http://{self.host}:{self.port}"

    def new_token(self):
        return uuid.uuid4().hex[:16]

    def payload_url(self, token=None):
        token = token or self.new_token()
        return token, f"{self.base_url}/{token}"

    def interactions(self, token):
        with self._lock:
            return list(self._interactions.get(token, []))

    def hit_count(self, token):
        with self._lock:
            return len(self._interactions.get(token, []))

    def wait_for_hit(self, token, timeout=5.0, poll=0.1):
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
