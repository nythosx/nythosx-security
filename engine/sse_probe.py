"""Server-Sent Events (SSE) security probe.

Discovers SSE endpoints, then subscribes with two identities and diffs
the event streams. A cross-user leak -- user_a receives events intended
for user_b -- is a missing-authorization finding that classic HTTP probes
miss because SSE is a long-lived GET with no per-event authorization
check on the wire.

Every outbound request routes through engine.http (scope gate + rate
limiter + budget). The streaming read reaches into the underlying httpx
client after the public pre-check so the initial connect is still gated.
"""
from __future__ import annotations

import hashlib
import json
import time
from urllib.parse import urlparse

from .chain_engine import register_tool
from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEViolation
from . import http as _http


CAPABILITY = Capability(
    name="sse_scan",
    description=("Discover Server-Sent Events endpoints and check for "
                 "cross-user event disclosure by subscribing with two "
                 "distinct identities and diffing the streams."),
    category="access-control",
    cost="medium",
    destructive=False,
    idempotent=True,
)


COMMON_SSE_PATHS = [
    "/events", "/api/events", "/stream", "/api/stream",
    "/sse", "/api/sse", "/subscribe", "/api/subscribe",
    "/notifications", "/api/notifications",
    "/messages/stream", "/api/messages/stream",
    "/updates", "/api/updates",
    "/live", "/api/live",
]


_MAX_LISTEN_SECONDS = 4.0
_MAX_LINE_BYTES = 8192


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _headers_for(identity_headers):
    h = {"Accept": "text/event-stream", "Cache-Control": "no-cache"}
    if identity_headers:
        h.update(identity_headers)
    return h


def _looks_like_sse(content_type, first_chunk):
    ct = (content_type or "").lower()
    if "text/event-stream" in ct:
        return True
    if not first_chunk:
        return False
    head = first_chunk.lstrip()
    if head.startswith(("data:", "event:", "id:", "retry:", ":")):
        return True
    return False


def _parse_sse_event(block):
    out = {"event": "message", "data": "", "id": None, "raw": block[:800]}
    data_lines = []
    for line in block.split("\n"):
        if not line or line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        field = field.strip()
        if field == "data":
            data_lines.append(value)
        elif field == "event":
            out["event"] = value
        elif field == "id":
            out["id"] = value
    out["data"] = "\n".join(data_lines)
    return out


def _events_hash(events):
    blob = json.dumps(
        [{"e": e.get("event"), "d": e.get("data")} for e in events],
        sort_keys=True, default=str,
    )
    return hashlib.sha256(blob.encode("utf-8", "ignore")).hexdigest()[:16]


def discover(base_url, headers=None, timeout=6, extra_paths=None):
    verify = _verify_tls()
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    paths = list(COMMON_SSE_PATHS) + list(extra_paths or [])
    hits = []
    seen = set()
    for path in paths:
        url = origin + path
        if url in seen:
            continue
        seen.add(url)
        req_headers = _headers_for(headers)
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.get(url, headers=req_headers)
        except _http.ROEBlock:
            continue
        except Exception:
            continue
        first_chunk = (r.text or "")[:512]
        if _looks_like_sse(r.headers.get("Content-Type", ""), first_chunk):
            hits.append({
                "url": url,
                "status": r.status_code,
                "content_type": r.headers.get("Content-Type", ""),
                "preview": first_chunk[:200],
            })
    return hits


def _read_stream(stream_url, headers, timeout, max_seconds, verify):
    events = []
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            c._pre("GET", stream_url)
            with c._client.stream("GET", stream_url, headers=headers,
                                   follow_redirects=False) as resp:
                if resp.status_code != 200:
                    return {"status": resp.status_code, "events": [],
                            "error": None}
                deadline = time.monotonic() + max_seconds
                buffer = ""
                for chunk in resp.iter_text():
                    if time.monotonic() > deadline:
                        break
                    buffer += chunk
                    if len(buffer) > _MAX_LINE_BYTES * 32:
                        buffer = buffer[-_MAX_LINE_BYTES * 32:]
                    while "\n\n" in buffer:
                        event_block, buffer = buffer.split("\n\n", 1)
                        events.append(_parse_sse_event(event_block))
                    if len(events) >= 100:
                        break
    except _http.ROEBlock as e:
        return {"status": None, "events": [], "error": f"ROE_BLOCK: {e}"}
    except Exception as e:
        return {"status": None, "events": [],
                "error": f"{type(e).__name__}: {e}"}
    return {"status": 200, "events": events, "error": None}


def scan(target_url, headers_a=None, headers_b=None, timeout=6,
         max_seconds=_MAX_LISTEN_SECONDS, roe_guard=None, extra_paths=None):
    verify = _verify_tls()
    if roe_guard is not None:
        try:
            roe_guard.check_url(target_url, "GET")
        except ROEViolation as e:
            return ScanResult(
                capability="sse_scan", target=target_url,
                verdict="UNKNOWN", reason=f"ROE_BLOCK: {e}",
            )
    hits = discover(target_url, headers=headers_a, timeout=timeout,
                    extra_paths=extra_paths)
    if not hits:
        return ScanResult(
            capability="sse_scan", target=target_url,
            verdict="PASS", severity="low",
            reason="no SSE endpoints detected",
            evidence={"tested": len(COMMON_SSE_PATHS)},
        )
    if not headers_b:
        return ScanResult(
            capability="sse_scan", target=target_url,
            verdict="SUSPICIOUS", severity="low",
            reason=(f"{len(hits)} SSE endpoint(s) found but only one "
                    f"identity available -- cross-user diff skipped"),
            evidence={"hits": hits},
        )
    findings = []
    for hit in hits:
        url = hit["url"]
        a = _read_stream(url, _headers_for(headers_a), timeout, max_seconds,
                         verify)
        b = _read_stream(url, _headers_for(headers_b), timeout, max_seconds,
                         verify)
        if a.get("error") or b.get("error"):
            continue
        ha = _events_hash(a["events"])
        hb = _events_hash(b["events"])
        if ha != hb and (a["events"] or b["events"]):
            findings.append({
                "url": url,
                "events_a": len(a["events"]),
                "events_b": len(b["events"]),
                "hash_a": ha,
                "hash_b": hb,
                "sample_a": a["events"][:2],
                "sample_b": b["events"][:2],
            })
    if findings:
        return ScanResult(
            capability="sse_scan", target=target_url,
            verdict="VULNERABLE", severity="high",
            reason=(f"cross-user SSE event disclosure on "
                    f"{len(findings)} endpoint(s)"),
            evidence={"findings": findings, "hits": hits},
        )
    return ScanResult(
        capability="sse_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=("SSE endpoints found but event streams did not differ "
                "between users"),
        evidence={"hits": hits},
    )


def _tool_sse_scan(orch, args):
    base = args.get("base_url") or orch.get_fact("api_base") or orch.target
    headers_a = None
    headers_b = None
    broker = getattr(orch, "identity_broker", None)
    if broker is not None:
        try:
            ctx_a = broker.get_identity("user_a")
            ctx_b = broker.get_identity("user_b")
            if ctx_a:
                headers_a = ctx_a.get_headers()
            if ctx_b:
                headers_b = ctx_b.get_headers()
        except Exception:
            pass
    if not headers_a:
        token = orch.get_context("jwt_token")
        if token:
            headers_a = {"Authorization": f"Bearer {token}"}
    extra = args.get("paths")
    if isinstance(extra, str):
        extra = [p.strip() for p in extra.split(",") if p.strip()]
    try:
        r = scan(base, headers_a=headers_a, headers_b=headers_b,
                 roe_guard=getattr(orch, "roe_guard", None),
                 extra_paths=extra)
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"sse_scan failed: {type(e).__name__}: {e}",
                "evidence": {}}
    return {"verdict": r["verdict"], "reason": r.reason,
            "evidence": r.evidence or {}}


register_tool("sse_scan", _tool_sse_scan)


__all__ = ["scan", "discover", "CAPABILITY", "_parse_sse_event",
           "_looks_like_sse", "_events_hash"]
