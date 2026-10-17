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
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import external_http


_CMD_OUTPUT_RE = re.compile(
    r"\buid=\d+\b|\bgid=\d+\b|\bgroups=\S+|^root:[^:]+:\d+:",
    re.MULTILINE,
)


def looks_like_command_output(text):
    if not text:
        return False
    try:
        return _CMD_OUTPUT_RE.search(text) is not None
    except Exception:
        return False


class _Collector(BaseHTTPRequestHandler):
    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except Exception:
            return b""
        if length <= 0:
            return b""
        try:
            return self.rfile.read(min(length, 65536))
        except Exception:
            return b""

    def _record(self):
        token = self.path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
        body = self._read_body()
        interaction = {
            "token": token,
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "client": self.client_address[0],
            "time": time.time(),
            "body": body,
            "body_text": body.decode("utf-8", "replace")[:8192]
                if body else "",
        }
        self.server.oob._add(token, interaction)
        if body:
            self.server.oob._add_output(token, body)
        if self.command == "GET" and self.path.rstrip("/").endswith("/next"):
            cmd = self.server.oob._pop_command(token)
            if cmd:
                data = cmd.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except Exception:
                    pass
                return
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body_out = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_out)))
        self.end_headers()
        try:
            self.wfile.write(body_out)
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
        self._outputs = defaultdict(list)
        self._commands = defaultdict(deque)
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
        with self._lock:
            self._outputs.clear()
            self._commands.clear()

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

    def _add_output(self, token, body):
        if not body:
            return
        with self._lock:
            self._outputs[token].append(bytes(body))

    def poll_output(self, token):
        with self._lock:
            chunks = list(self._outputs.get(token, []))
        return b"".join(chunks)

    def output_for(self, token):
        return self.poll_output(token)

    def clear_output(self, token):
        with self._lock:
            self._outputs.pop(token, None)

    def send_command(self, token, command):
        if not token or command is None:
            return False
        with self._lock:
            self._commands[token].append(str(command))
        return True

    def _pop_command(self, token):
        with self._lock:
            q = self._commands.get(token)
            if not q:
                return None
            return q.popleft()

    def wait_for_output(self, token, timeout=5.0, poll=0.5):
        if self._external_url:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if self._poll_external(token):
                    return True
                time.sleep(poll)
            return False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._outputs.get(token):
                    return True
            time.sleep(poll)
        with self._lock:
            return bool(self._outputs.get(token))

    def _poll_external(self, token):
        if not self._external_url:
            return False
        try:
            poll_url = f"{self._external_url.rstrip('/')}/poll?token={token}"
            with external_http.Client(timeout=3.0, follow_redirects=True) as c:
                r = c.get(poll_url)
                if r.status_code == 200:
                    data = r.json()
                    return bool(data.get("hit") or data.get("hits") or data.get("interactions"))
        except Exception:
            pass
        return False

    def wait_for_hit(self, token, timeout=5.0, poll=0.5):
        if self._external_url:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if self._poll_external(token):
                    return True
                time.sleep(poll)
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


__all__ = ["OOBServer", "looks_like_command_output"]
