import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import cloud_storage


class _BucketServer(BaseHTTPRequestHandler):
    """Simulates a subset of S3 behaviour.

    /publicbucket/          -> 200 XML listing
    /privatebucket/         -> 403
    /availablebucket/       -> 404 NoSuchBucket
    /existsbucket/          -> 200 HTML default page
    anything else           -> 404
    """
    def do_GET(self):
        path = self.path.strip("/").split("/")[0]
        if path == "publicbucket":
            body = (b'<?xml version="1.0"?><ListBucketResult>'
                    b'<Contents><Key>secret.txt</Key></Contents>'
                    b'</ListBucketResult>')
            self.send_response(200)
        elif path == "privatebucket":
            body = b'<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>'
            self.send_response(403)
        elif path == "availablebucket":
            body = (b'<?xml version="1.0"?><Error><Code>NoSuchBucket</Code>'
                    b'<Message>The specified bucket does not exist</Message></Error>')
            self.send_response(404)
        elif path == "existsbucket":
            body = b"<html><body>Default page</body></html>"
            self.send_response(200)
        else:
            body = b""
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _BucketServer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_candidate_buckets():
    buckets = cloud_storage.candidate_buckets("example.com")
    assert "example" in buckets
    assert "example-backup" in buckets
    assert "example-prod" in buckets


def test_candidate_buckets_url_input():
    buckets = cloud_storage.candidate_buckets("https://example.com/path")
    assert "example" in buckets


def test_candidate_buckets_subdomain():
    buckets = cloud_storage.candidate_buckets("api.example.com")
    assert "example" in buckets


def test_base_name_empty():
    assert cloud_storage.candidate_buckets("") == []


def test_classify_public():
    body = '<?xml version="1.0"?><ListBucketResult><Contents><Key>a</Key></Contents></ListBucketResult>'
    assert cloud_storage.classify(200, body) == "public"


def test_classify_private():
    assert cloud_storage.classify(403, "") == "private"


def test_classify_available():
    body = '<Error><Code>NoSuchBucket</Code></Error>'
    assert cloud_storage.classify(404, body) == "available"


def test_classify_exists():
    assert cloud_storage.classify(200, "<html>hi</html>") == "exists"


def test_classify_unreachable():
    assert cloud_storage.classify(None, "") == "unreachable"


def test_public_bucket_flagged():
    srv = _serve()
    _, port = srv.server_address
    endpoints = [{"provider": "s3",
                  "url_template": f"http://127.0.0.1:{port}/{{bucket}}/"}]
    try:
        r = cloud_storage.scan(
            "publicbucket.com", endpoints=endpoints,
            max_buckets=1)
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
    assert r.evidence["public"][0]["bucket"] == "publicbucket"


def test_available_bucket_informational_not_flagged():
    srv = _serve()
    _, port = srv.server_address
    endpoints = [{"provider": "s3",
                  "url_template": f"http://127.0.0.1:{port}/{{bucket}}/"}]
    try:
        r = cloud_storage.scan(
            "availablebucket.com", endpoints=endpoints, max_buckets=1)
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "PASS"
    assert r.evidence["available"][0]["bucket"] == "availablebucket"
    assert "informational" in r["reason"]


def test_private_bucket_passes():
    srv = _serve()
    _, port = srv.server_address
    endpoints = [{"provider": "s3",
                  "url_template": f"http://127.0.0.1:{port}/{{bucket}}/"}]
    try:
        r = cloud_storage.scan(
            "privatebucket.com", endpoints=endpoints, max_buckets=1)
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "PASS"
    assert r.evidence["private"][0]["bucket"] == "privatebucket"


def test_no_matches_passes():
    srv = _serve()
    _, port = srv.server_address
    endpoints = [{"provider": "s3",
                  "url_template": f"http://127.0.0.1:{port}/{{bucket}}/"}]
    try:
        r = cloud_storage.scan(
            "unrelated-name.invalid", endpoints=endpoints, max_buckets=1)
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "PASS"
