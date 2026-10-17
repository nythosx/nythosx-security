"""Loopback fixtures for Tier-2 Phase 2 desync tests.

Two servers:

  DesyncFixture  -- raw TCP h1 server with /tunnel/vulnerable (parses CL.TE
                    and answers with a second response carrying the
                    smuggled path) and /tunnel/clean (400 on CL+TE).
  H2Fixture      -- h2c (prior-knowledge) server with /h2/strict (rejects
                    CL:0 with DATA and CRLF in :path) and /h2/lenient
                    (accepts both).
"""
from __future__ import annotations

import contextlib
import socket
import threading

try:
    import h2.connection
    import h2.config
    import h2.events
    HAS_H2 = True
except ImportError:
    HAS_H2 = False


# --- Raw desync fixture (h1, cleartext) -----------------------------------

class _DesyncServer:
    def __init__(self):
        self.sock = None
        self.port = 0
        self.thread = None
        self.requests = []

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(10)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    def _handle(self, conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
                if len(data) > 65536:
                    return
            head, _, rest = data.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            if not lines:
                return
            parts = lines[0].split(b" ")
            path = parts[1].decode("latin-1") if len(parts) >= 2 else "/"
            headers = {}
            for line in lines[1:]:
                if b":" not in line:
                    continue
                name, _, val = line.partition(b":")
                headers[name.strip().lower().decode("latin-1")] = \
                    val.strip().decode("latin-1")
            cl = None
            try:
                cl = int(headers.get("content-length") or 0)
            except ValueError:
                cl = None
            while cl is not None and len(rest) < cl:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                rest += chunk
            body = rest[:cl] if cl is not None else rest
            self.requests.append({"path": path, "headers": headers,
                                   "body": body[:200]})
            if path.startswith("/tunnel/vulnerable"):
                self._respond_vulnerable(conn, headers, body)
            elif path.startswith("/tunnel/clean"):
                conn.sendall(self._resp(400, b"ambiguous CL+TE"))
            else:
                conn.sendall(self._resp(404, b"not found"))
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def _respond_vulnerable(self, conn, headers, body):
        # Always answer the prefix request.
        if headers.get("transfer-encoding", "").lower() == "chunked" \
                and headers.get("content-length"):
            # Desync target: TE wins for the body boundary.
            conn.sendall(self._resp(200, b"ok"))
            # Look for the smuggled request after 0\r\n\r\n
            marker = b"\r\n0\r\n\r\n"
            idx = body.find(marker)
            start = idx + len(marker) if idx >= 0 else 0
            if body.startswith(b"0\r\n\r\n"):
                start = 5
            smuggled = body[start:]
            if smuggled.startswith((b"GET ", b"POST ")):
                first = smuggled.split(b"\r\n", 1)[0]
                parts = first.split(b" ")
                spath = parts[1].decode("latin-1") if len(parts) >= 2 else "/"
                extra = b""
                midx = smuggled.find(b"X-Tunnel-Marker:")
                if midx >= 0:
                    line_end = smuggled.find(b"\r\n", midx)
                    extra = smuggled[midx:line_end]
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 12\r\n"
                    b"X-Smuggled-Path: " + spath.encode() + b"\r\n"
                    b"X-Smuggled-Extra: " + extra + b"\r\n"
                    b"Connection: close\r\n\r\n"
                    b"smuggled-ok"
                )
                conn.sendall(resp)
        else:
            conn.sendall(self._resp(200, b"ok"))

    def _resp(self, status, body):
        head = (
            "HTTP/1.1 %d X\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n"
        ) % (status, len(body))
        return head.encode() + body

    def stop(self):
        with contextlib.suppress(Exception):
            self.sock.close()


class DesyncFixture:
    def __init__(self):
        self._srv = _DesyncServer()

    @property
    def base_url(self):
        return "http://127.0.0.1:%d" % self._srv.port

    @property
    def requests(self):
        return self._srv.requests

    def start(self):
        self._srv.start()
        return self

    def stop(self):
        self._srv.stop()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


# --- H2 fixture (h2c prior knowledge) -------------------------------------

class _H2Server:
    def __init__(self):
        self.sock = None
        self.port = 0
        self.thread = None

    def start(self):
        if not HAS_H2:
            raise RuntimeError("h2 library not installed")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(10)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    def _handle(self, conn):
        try:
            cfg = h2.config.H2Configuration(
                client_side=False,
                validate_inbound_headers=False,
                normalize_inbound_headers=False,
            )
            conn_h2 = h2.connection.H2Connection(config=cfg)
            conn_h2.initiate_connection()
            conn.sendall(conn_h2.data_to_send())
            conn.settimeout(5)
            streams = {}
            responded = set()
            while True:
                try:
                    data = conn.recv(65535)
                except socket.timeout:
                    break
                if not data:
                    break
                try:
                    events = conn_h2.receive_data(data)
                except Exception:
                    break
                for ev in events:
                    if isinstance(ev, h2.events.RequestReceived):
                        sid = ev.stream_id
                        streams[sid] = {
                            "headers": dict(ev.headers),
                            "body": b"",
                        }
                        # Respond immediately from headers alone.
                        # This is required for CL:0 + body probes,
                        # because h2 rejects the DATA frame; the
                        # response must be sent before the client
                        # sends (or the server processes) the
                        # malformed data.
                        if sid not in responded:
                            status, body_out = self._decide(
                                streams[sid])
                            try:
                                conn_h2.send_headers(sid, [
                                    (b":status",
                                     str(status).encode()),
                                    (b"content-length",
                                     str(len(body_out)).encode()),
                                ], end_stream=(len(body_out) == 0))
                                if body_out:
                                    conn_h2.send_data(
                                        sid, body_out,
                                        end_stream=True)
                            except Exception:
                                pass
                            responded.add(sid)
                    elif isinstance(ev, h2.events.DataReceived):
                        sid = ev.stream_id
                        if sid in streams:
                            streams[sid]["body"] += ev.data
                        try:
                            conn_h2.acknowledge_received_data(
                                ev.flow_controlled_length, sid)
                        except Exception:
                            pass
                    elif isinstance(ev, h2.events.StreamEnded):
                        # Already responded at RequestReceived.
                        pass
                out = conn_h2.data_to_send()
                if out:
                    conn.sendall(out)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def _decide(self, req):
        # Called at RequestReceived time, so body bytes are not
        # yet available. All decisions are based on headers alone.
        headers = req["headers"]
        path_b = headers.get(b":path") or headers.get(":path") or b""
        cl_b = headers.get(b"content-length") or \
            headers.get("content-length") or b""
        if isinstance(path_b, bytes):
            path = path_b.decode("latin-1", "replace")
        else:
            path = str(path_b)
        if isinstance(cl_b, bytes):
            cl = cl_b.decode("latin-1", "replace")
        else:
            cl = str(cl_b)
        path_has_crlf = "\r" in path or "\n" in path
        has_te = (
            (headers.get(b"transfer-encoding") or
             headers.get("transfer-encoding")) is not None
        )
        strict = path.startswith("/h2/strict")
        if strict:
            if path_has_crlf:
                return 400, b"bad path"
            if cl == "0":
                return 400, b"cl0"
            if has_te:
                return 400, b"te+cl"
            return 200, b"ok strict"
        if path_has_crlf:
            return 200, b"path_injected"
        if cl == "0":
            return 200, b"cl0_accepted"
        if has_te:
            return 200, b"te_cl_accepted"
        return 200, b"ok lenient"

    def stop(self):
        with contextlib.suppress(Exception):
            self.sock.close()


class H2Fixture:
    def __init__(self):
        self._srv = _H2Server()

    @property
    def base_url(self):
        return "http://127.0.0.1:%d" % self._srv.port

    def start(self):
        self._srv.start()
        return self

    def stop(self):
        self._srv.stop()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
