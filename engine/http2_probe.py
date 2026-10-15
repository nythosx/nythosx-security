from __future__ import annotations

import socket
import ssl as ssl_mod
import time
from urllib.parse import urlparse

from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEGuard, ROEViolation

try:
    import h2.connection
    import h2.config
    import h2.events
    HAS_H2 = True
except ImportError:
    HAS_H2 = False


CAPABILITY = Capability(
    name="http2_scan",
    description="HTTP/2 desync probes: H2.CL, H2.TE, rapid reset.",
    category="temporal",
    cost="medium",
    destructive=False,
    idempotent=True,
)


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="POST"):
    if guard is None:
        try:
            guard = ROEGuard(engine_cfg=load_engine())
        except Exception as e:
            return f"ROE guard unavailable (fail-closed): {e}"
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def _connect(host, port, use_tls, verify, timeout):
    try:
        ctx = ssl_mod.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            sock = ctx.wrap_socket(raw, server_hostname=host)
            if sock.selected_alpn_protocol() != "h2":
                sock.close()
                return None, f"server did not negotiate h2"
            return sock, None
        return raw, None
    except ConnectionRefusedError:
        return None, "connection refused"
    except socket.timeout:
        return None, f"timeout after {timeout}s"
    except OSError as e:
        return None, f"network error: {e}"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _probe_h2(url, method="POST", body=b"", extra_headers=None,
              timeout=8, verify=True):
    if not HAS_H2:
        return {"ok": False, "error": "h2 library not installed"}
    p = urlparse(url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    use_tls = p.scheme == "https"
    path = p.path or "/"
    if p.query:
        path += "?" + p.query

    sock, err = _connect(host, port, use_tls, verify, timeout)
    if err:
        return {"ok": False, "error": err}

    try:
        cfg = h2.config.H2Configuration(client_side=True)
        conn = h2.connection.H2Connection(config=cfg)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        headers = [
            (":method", method.upper()),
            (":authority", host),
            (":scheme", "https" if use_tls else "http"),
            (":path", path),
        ]
        if body:
            headers.append(("content-length", str(len(body))))
        for k, v in (extra_headers or {}).items():
            headers.append((k.lower(), str(v)))

        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, headers, end_stream=False)
        if body:
            conn.send_data(sid, body, end_stream=False)
        conn.send_data(sid, b"", end_stream=True)
        sock.sendall(conn.data_to_send())

        sock.settimeout(timeout)
        deadline = time.monotonic() + timeout
        status = None
        body_recv = b""
        while time.monotonic() < deadline:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                break
            if not data:
                break
            events = conn.receive_data(data)
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    status = dict(ev.headers).get(":status")
                elif isinstance(ev, h2.events.DataReceived):
                    body_recv += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length,
                                                    ev.stream_id)
                elif isinstance(ev, (h2.events.StreamEnded,
                                      h2.events.StreamReset)):
                    return {"ok": True, "status": int(status) if status else None,
                            "body_len": len(body_recv)}
            out = conn.data_to_send()
            if out:
                sock.sendall(out)

        return {"ok": True, "status": int(status) if status else None,
                "body_len": len(body_recv)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def scan(target_url, method="POST", headers=None, roe_guard=None,
         timeout=8, rapid_reset_count=10):
    verify = _verify_tls()
    cfg = (load_engine() or {}).get("http2") or {}
    if not cfg.get("enabled", True):
        return ScanResult(
            capability="http2_scan", target=target_url,
            verdict="UNKNOWN", reason="http2.enabled=false",
        )
    if not HAS_H2:
        return ScanResult(
            capability="http2_scan", target=target_url,
            verdict="UNKNOWN", reason="h2 library not installed",
        )
    viol = _roe_block(roe_guard, target_url, method)
    if viol:
        return ScanResult(
            capability="http2_scan", target=target_url,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )

    baseline = _probe_h2(target_url, method=method,
                          body=b"sec-checker-baseline",
                          extra_headers=headers, timeout=timeout,
                          verify=verify)
    if not baseline.get("ok"):
        return ScanResult(
            capability="http2_scan", target=target_url,
            verdict="UNKNOWN",
            reason=f"HTTP/2 baseline failed: {baseline.get('error')}",
        )
    if baseline.get("status") is None:
        return ScanResult(
            capability="http2_scan", target=target_url,
            verdict="UNKNOWN",
            reason="HTTP/2 baseline probe did not receive a valid response header",
            evidence={"baseline": baseline},
        )
    if baseline.get("status") in (404, 410, 405, 501):
        return ScanResult(
            capability="http2_scan", target=target_url,
            verdict="UNKNOWN",
            reason=(f"HTTP/2 baseline returned {baseline.get('status')} — "
                    f"endpoint not found or method not accepted"),
            evidence={"baseline": baseline},
        )

    findings = []

    h2cl = _probe_h2(target_url, method=method, body=b"0\r\n\r\n",
                     extra_headers={
                         **(headers or {}),
                         "content-length": "4",
                         "transfer-encoding": "chunked",
                     },
                     timeout=timeout, verify=verify)
    if h2cl.get("ok") and h2cl.get("status") == 200:
        findings.append({"vector": "H2.CL",
                         "status": h2cl.get("status")})

    h2te = _probe_h2(target_url, method=method, body=b"4\r\nABCD\r\n0\r\n\r\n",
                     extra_headers={
                         **(headers or {}),
                         "content-length": "0",
                         "transfer-encoding": "chunked",
                     },
                     timeout=timeout, verify=verify)
    if h2te.get("ok") and h2te.get("status") == 200:
        findings.append({"vector": "H2.TE",
                         "status": h2te.get("status")})

    if findings:
        return ScanResult(
            capability="http2_scan", target=target_url,
            verdict="SUSPICIOUS", severity="medium",
            reason=f"HTTP/2 desync vectors accepted: {[f['vector'] for f in findings]}",
            evidence={"findings": findings, "baseline": baseline},
        )
    return ScanResult(
        capability="http2_scan", target=target_url,
        verdict="PASS", severity="low",
        reason="no HTTP/2 desync vectors accepted",
        evidence={"baseline": baseline},
    )


__all__ = ["scan", "probe_h2", "CAPABILITY"]
