"""Drupal-mimic fixture app for Phase 7 acceptance tests.

Served on 127.0.0.1 (in ROE scope). Deliberately misconfigured surfaces:

  GET /user/{uid}                       weak access control (name + email)
  GET /jsonapi/node/secret_content      anonymous JSON:API read (restricted)
  GET /update.php                       returns 200 (should be 403/auth)
  GET /storage/108/backup.sql           sensitive file in public storage
  GET /CHANGELOG.txt                    Drupal version string
  GET /sites/default/settings.php       readable (DB creds) — config leak

Everything else returns a stable 404 so the soft-404 fingerprint is clean.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

_USERS = {
    1: {"name": "admin", "mail": "admin@uni.edu.ph", "roles": ["administrator"]},
    2: {"name": "jdelacruz", "mail": "j.delacruz@uni.edu.ph",
        "roles": ["faculty"]},
    3: {"name": "msantos", "mail": "m.santos@uni.edu.ph", "roles": ["student"]},
}

_SETTINGS_PHP = (
    "<?php\n$databases['default']['default'] = array(\n"
    "  'database' => 'drupal',\n  'username' => 'drupaluser',\n"
    "  'password' => 'S3cr3tDbP@ss',\n  'host' => 'localhost',\n);\n")

_BACKUP_SQL = (
    "-- MySQL dump\nINSERT INTO users VALUES "
    "(1,'admin','admin@uni.edu.ph','$2y$10$abcdef'),"
    "(2,'jdelacruz','j.delacruz@uni.edu.ph','4111111111111234');\n"
    "SET PASSWORD = 'S3cr3tDbP@ss';\n")

_CHANGELOG = "Drupal 9.4.8, 2022-08-03\n- Fixed a bug.\n"

_KEY_OFFICIALS = (
    "<html><body><ul>"
    "<li>Maria Santos</li><li>Jose Dela Cruz</li>"
    "<li>Ana Reyes</li></ul></body></html>")


class DrupalMimicHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(data)
            except Exception:
                pass

    def do_GET(self):
        path = urlparse(self.path).path

        if path.startswith("/user/"):
            tail = path[len("/user/"):]
            if tail.isdigit():
                uid = int(tail)
                u = _USERS.get(uid)
                if u:
                    return self._send(200, {"uid": uid, "name": u["name"],
                                            "mail": u["mail"],
                                            "roles": u["roles"]})
                return self._send(404, {"error": "no such user"})

        if path == "/jsonapi/node/secret_content":
            return self._send(200, {"jsonapi": {"version": "1.0"},
                                    "data": [{"type": "node--secret",
                                              "attributes":
                                              {"title": "Board minutes",
                                               "body": "confidential"}}]})
        if path in ("/jsonapi/node/article", "/node/1",
                    "/user/register"):
            return self._send(403, {"error": "access denied"})
        if path == "/jsonapi":
            return self._send(200, {"jsonapi": {"version": "1.0"}})

        if path == "/update.php":
            return self._send(200, "<h1>Drupal database update</h1>",
                              ctype="text/html")
        if path in ("/install.php", "/core/install.php", "/core/update.php"):
            return self._send(403, "forbidden", ctype="text/plain")

        if path == "/storage/108/backup.sql":
            return self._send(200, _BACKUP_SQL, ctype="application/sql")

        if path == "/CHANGELOG.txt":
            return self._send(200, _CHANGELOG, ctype="text/plain")

        if path == "/sites/default/settings.php":
            return self._send(200, _SETTINGS_PHP, ctype="text/plain")

        if path == "/administration/key-officials":
            return self._send(200, _KEY_OFFICIALS, ctype="text/html")

        if path == "/rest/session/token":
            return self._send(200, "aXAbc123token", ctype="text/plain")

        return self._send(404, {"error": "not found"})

    def do_HEAD(self):
        self.do_GET()


def start_drupal_mimic():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), DrupalMimicHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    return f"http://127.0.0.1:{port}", srv
