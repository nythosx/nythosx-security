"""Reverse proxy / origin boundary differential.

Sends ambiguous HTTP requests over a raw socket so we can craft headers
httpx refuses to build (duplicate Content-Length, CL+TE, obs-fold, NUL in
header names, etc.). Each probe result is classified into a "winning side"
so the desync_surface fact captures which side (frontend or backend)
decided each ambiguity.

ROE is checked per probe via the caller-supplied guard. Raw socket is used
because engine.http.Client (httpx) drops duplicate Content-Length on
construction — the same precedent as engine.smuggle.

Frontend class detection: reads Via, X-Varnish, X-Amz-Cf-Id, CF-Ray,
X-Served-By, Server on a clean request.
"""
from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

from ..config import load_engine
from ..roe_guard import ROEGuard, ROEViolation


FRONTEND_CLASS_HEADERS = (
    ("via", ["varnish", "squid", "akamai"]),
    ("x-varnish", ["varnish"]),
    ("x-amz-cf-id", ["cloudfront"]),
    ("cf-ray", ["cloudflare"]),
    ("x-served-by", ["fastly"]),
    ("x-akamai-transformed", ["akamai"]),
    ("server", ["nginx", "apache", "cloudflare", "akamai", "iis",
                 "caddy", "traefik", "envoy"]),
)


EXPLOITABLE_AMBIGUITIES = {
    "dup_cl_disagree": lambda v: v in ("cl_first", "cl_last"),
    "cl_te_conflict": lambda v: v in ("cl", "te"),
    "dup_te": lambda v: v in ("te_first", "te_last"),
    "obs_fold": lambda v: v == "lenient",
    "ws_before_colon": lambda v: v == "lenient",
}


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
            return "ROE guard unavailable (fail-closed): %s" % e
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def _raw_send(url, request_bytes, timeout=5, roe_guard=None):
    viol = _roe_block(roe_guard, url, "POST")
    if viol:
        return {"blocked": True, "error": "ROE_BLOCK: " + viol}
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
    except Exception as e:
        return {"error": "%s: %s" % (type(e).__name__, e)}
    try:
        sock.sendall(request_bytes)
        sock.settimeout(timeout)
        resp = b""
        while len(resp) < 100000:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            resp += chunk
        try:
            sock.close()
        except Exception:
            pass
        return {"raw": resp}
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return {"error": "%s: %s" % (type(e).__name__, e)}


def _parse_response(raw):
    if not raw:
        return {"status": 0, "headers": {}, "body": ""}
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = 0
    if lines:
        parts = lines[0].split(b" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, _, val = line.partition(b":")
        try:
            k = name.strip().lower().decode("latin-1")
            v = val.strip().decode("latin-1")
        except Exception:
            continue
        headers.setdefault(k, v)
    try:
        body_str = body.decode("utf-8", "replace")
    except Exception:
        body_str = ""
    return {"status": status, "headers": headers, "body": body_str[:8000]}


def detect_frontend_class(url, timeout=5, roe_guard=None):
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return "unknown"
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"
    path = parsed.path or "/"
    req = (
        b"GET " + path.encode() + b" HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"User-Agent: sec-checker-boundary\r\n"
        b"Connection: close\r\n\r\n"
    )
    r = _raw_send(url, req, timeout=timeout, roe_guard=roe_guard)
    if "raw" not in r:
        return "unknown"
    resp = _parse_response(r["raw"])
    headers = resp.get("headers") or {}
    for hname, needles in FRONTEND_CLASS_HEADERS:
        val = headers.get(hname, "")
        if not val:
            continue
        vlow = val.lower()
        for n in needles:
            if n in vlow:
                return n
    return "unknown"


def _probes():
    """Return list of ambiguity probe specs.

    Each spec: {"id", "description", "build": fn(host, path) -> bytes}.
    The exact wire bytes matter — this is the entire point of the module.
    """
    return [
        {
            "id": "dup_cl_agree",
            "description": "Two Content-Length headers with the same value",
            "build": lambda host, path: (
                b"POST " + path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"Content-Length: 5\r\n"
                b"Content-Length: 5\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"hello"
            ),
        },
        {
            "id": "dup_cl_disagree",
            "description": "Two Content-Length headers with different values",
            "build": lambda host, path: (
                b"POST " + path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"Content-Length: 5\r\n"
                b"Content-Length: 6\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"hello!"
            ),
        },
        {
            "id": "dup_te",
            "description": "Two Transfer-Encoding headers",
            "build": lambda host, path: (
                b"POST " + path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Transfer-Encoding: gzip\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"0\r\n\r\n"
            ),
        },
        {
            "id": "cl_te_conflict",
            "description": "Content-Length + Transfer-Encoding chunked",
            "build": lambda host, path: (
                b"POST " + path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"Content-Length: 6\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"5\r\nhello\r\n0\r\n\r\n"
            ),
        },
        {
            "id": "obs_fold",
            "description": "Obs-fold continuation line",
            "build": lambda host, path: (
                b"POST " + path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"X-Folded: value1\r\n"
                b" continuation\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            ),
        },
        {
            "id": "ws_before_colon",
            "description": "Whitespace before the header colon",
            "build": lambda host, path: (
                b"POST " + path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"X-Forwarded-For : 127.0.0.1\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            ),
        },
        {
            "id": "tab_after_colon",
            "description": "Tab after the header colon",
            "build": lambda host, path: (
                b"POST " + path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"X-Forwarded-For:\t127.0.0.1\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            ),
        },
        {
            "id": "nul_in_header",
            "description": "NUL byte in header value",
            "build": lambda host, path: (
                b"POST " + path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"X-Probe: value\x00tail\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            ),
        },
        {
            "id": "te_obfuscation",
            "description": "Transfer-Encoding with x-chunked obfuscation",
            "build": lambda host, path: (
                b"POST " + path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"Transfer-Encoding: xchunked\r\n"
                b"Content-Length: 5\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"hello"
            ),
        },
        {
            "id": "clean",
            "description": "Clean baseline (control)",
            "build": lambda host, path: (
                b"POST " + path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"Content-Length: 5\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"hello"
            ),
        },
    ]


def _classify(probe_id, resp):
    status = resp.get("status")
    headers = resp.get("headers") or {}
    body = (resp.get("body") or "").lower()
    winner = headers.get("x-winner", "").lower().strip()
    if winner:
        return winner
    if status == 400 or status == 501:
        return "strict"
    if status == 200:
        if "cl_winner" in body or "winner=cl" in body:
            return "cl"
        if "te_winner" in body or "winner=te" in body:
            return "te"
        return "lenient"
    if status == 0:
        return "unreachable"
    return "unclear"


def probe_ambiguity(url, timeout=5, roe_guard=None):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    frontend_class = detect_frontend_class(url, timeout=timeout,
                                             roe_guard=roe_guard)
    probes = []
    for spec in _probes():
        req_bytes = spec["build"](host, path)
        r = _raw_send(url, req_bytes, timeout=timeout, roe_guard=roe_guard)
        if r.get("blocked"):
            return {"blocked": True, "error": r["error"],
                    "frontend_class": frontend_class, "probes": probes}
        if "raw" not in r:
            probes.append({
                "id": spec["id"], "description": spec["description"],
                "error": r.get("error", "no response"),
            })
            continue
        resp = _parse_response(r["raw"])
        probes.append({
            "id": spec["id"],
            "description": spec["description"],
            "response": {"status": resp.get("status"),
                          "headers": resp.get("headers"),
                          "body": resp.get("body", "")[:500]},
            "classification": _classify(spec["id"], resp),
        })
    return {"frontend_class": frontend_class, "probes": probes}


def analyze_winner_matrix(probes):
    winning = {}
    exploitable = []
    for probe in probes:
        pid = probe.get("id")
        cls = probe.get("classification")
        if not pid or cls is None:
            continue
        winning[pid] = cls
        check = EXPLOITABLE_AMBIGUITIES.get(pid)
        if check and check(cls):
            exploitable.append(pid)
    return {
        "winning_side": winning,
        "exploitable_ambiguities": exploitable,
    }


def extract_desync_surface(url, timeout=5, roe_guard=None):
    result = probe_ambiguity(url, timeout=timeout, roe_guard=roe_guard)
    if result.get("blocked"):
        return {"verdict": "UNKNOWN",
                "reason": result["error"],
                "evidence": {}}
    matrix = analyze_winner_matrix(result["probes"])
    desync_surface = {
        "frontend_class": result.get("frontend_class", "unknown"),
        "winning_side": matrix["winning_side"],
        "exploitable_ambiguities": matrix["exploitable_ambiguities"],
    }
    if matrix["exploitable_ambiguities"]:
        return {
            "verdict": "VULNERABLE",
            "reason": ("ambiguous CL/TE handling on %d vector(s): %s "
                       "(frontend: %s)" % (
                           len(matrix["exploitable_ambiguities"]),
                           ", ".join(matrix["exploitable_ambiguities"]),
                           desync_surface["frontend_class"])),
            "evidence": {
                "probes": result["probes"],
                "desync_surface": desync_surface,
            },
            "desync_surface": desync_surface,
        }
    live = [p for p in result["probes"] if p.get("response")]
    if not live:
        return {"verdict": "UNKNOWN",
                "reason": "no boundary probes completed",
                "evidence": {"probes": result["probes"]},
                "desync_surface": desync_surface}
    return {
        "verdict": "PASS",
        "reason": ("boundary parser consensus across %d vector(s) "
                   "(frontend: %s)" % (
                       len(live), desync_surface["frontend_class"])),
        "evidence": {"probes": result["probes"],
                     "desync_surface": desync_surface},
        "desync_surface": desync_surface,
    }
