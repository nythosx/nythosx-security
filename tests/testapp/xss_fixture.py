from __future__ import annotations

import contextlib
import html as _html
import http.server
import threading
import urllib.parse


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        q = (qs.get("q") or [""])[0]

        templates = {
            "/body": "<html><body>%s</body></html>",
            "/attr_double": '<input value="%s">',
            "/attr_single": "<input value='%s'>",
            "/attr_unquoted": "<input value=%s>",
            "/js_string": '<script>var x = "%s";</script>',
            "/js_template": '<script>var x = `%s`;</script>',
            "/comment": "<html><body><!-- %s --></body></html>",
            "/srcdoc": '<iframe srcdoc="%s"></iframe>',
            "/json_in_script":
                '<script type="application/json">{"x":"%s"}</script>',
            "/safe": "<html><body>%s</body></html>",
        }

        tmpl = templates.get(parsed.path)
        if tmpl is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if parsed.path == "/safe":
            body = tmpl % _html.escape(q)
        else:
            body = tmpl % q

        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class Fixture:
    def __init__(self):
        self.httpd = None
        self.thread = None
        self.base_url = ""

    def start(self):
        self.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _Handler)
        port = self.httpd.server_address[1]
        self.base_url = "http://127.0.0.1:%d" % port
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.httpd is not None:
            with contextlib.suppress(Exception):
                self.httpd.shutdown()
                self.httpd.server_close()
            self.httpd = None
            self.thread = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
