"""Non-destructive HTTP request smuggling detection via timing differentials.

Only the standard CL.TE / TE.CL timing probes are used: they cause the target's
back-end to briefly wait for bytes that never arrive on our own connection. No
second request is ever smuggled into another client's stream and no shared cache
is touched, so no third party is affected. Verdicts cap at SUSPICIOUS.
"""
import ssl
import time
import socket
from urllib.parse import urlparse

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation


def build_payload(kind, host, path="/"):
    path = path or "/"
    if kind == "baseline":
        body = ""
        headers = [f"POST {path} HTTP/1.1", f"Host: {host}",
                   "Content-Length: 0", "Connection: close"]
    elif kind == "clte":
        body = "1\r\nA\r\nX"
        headers = [f"POST {path} HTTP/1.1", f"Host: {host}",
                   "Transfer-Encoding: chunked", "Content-Length: 4",
                   "Connection: close"]
    elif kind == "tecl":
        body = "0\r\n\r\nX"
        headers = [f"POST {path} HTTP/1.1", f"Host: {host}",
                   "Transfer-Encoding: chunked", "Content-Length: 6",
                   "Connection: close"]
    else:
        raise ValueError(f"unknown payload kind: {kind}")
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode("latin-1")


def _send_raw(host, port, payload, use_tls=False, timeout=5.0, verify=False):
    result = {"elapsed_ms": 0.0, "received_bytes": 0, "timed_out": False,
              "error": None}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.sendall(payload)
        try:
            data = sock.recv(4096)
            result["received_bytes"] = len(data)
        except socket.timeout:
            result["timed_out"] = True
        result["elapsed_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return result


def analyze(baseline_ms, probes, threshold_ms=3000.0):
    findings = []
    for name, data in probes.items():
        if data.get("error"):
            continue
        delayed = data.get("timed_out") or \
            (data["elapsed_ms"] - baseline_ms) >= threshold_ms
        if delayed:
            findings.append({"vector": name, "elapsed_ms": data["elapsed_ms"],
                             "timed_out": data.get("timed_out", False)})
    if findings:
        vectors = ", ".join(f["vector"].upper() for f in findings)
        return {"verdict": "SUSPICIOUS",
                "reason": f"response delayed on ambiguous CL/TE header(s): {vectors} "
                          f"(baseline {baseline_ms:.0f}ms) — manual confirmation required",
                "evidence": {"baseline_ms": baseline_ms, "delayed": findings}}
    return {"verdict": "PASS",
            "reason": "no timing differential on ambiguous CL/TE headers",
            "evidence": {"baseline_ms": baseline_ms}}


def probe(target_url, engine_cfg=None, timeout=5.0, threshold_ms=3000.0,
          roe_guard=None):
    engine_cfg = engine_cfg if engine_cfg is not None else load_engine()
    guard = roe_guard or ROEGuard(engine_cfg=engine_cfg)
    try:
        guard.check_url(target_url, "POST")
    except ROEViolation as e:
        return {"target": target_url, "error": f"ROE_BLOCK: {e}",
                "result": {"verdict": "UNKNOWN", "reason": f"ROE_BLOCK: {e}",
                           "evidence": {}}}
    parts = urlparse(target_url)
    use_tls = parts.scheme == "https"
    host = parts.hostname or ""
    port = parts.port or (443 if use_tls else 80)
    path = parts.path or "/"
    verify = engine_cfg.get("http", {}).get("verify_tls", False)

    base = _send_raw(host, port, build_payload("baseline", host, path),
                     use_tls, timeout, verify)
    baseline_ms = 0.0 if base.get("error") else base["elapsed_ms"]
    probes = {
        "clte": _send_raw(host, port, build_payload("clte", host, path),
                          use_tls, timeout, verify),
        "tecl": _send_raw(host, port, build_payload("tecl", host, path),
                          use_tls, timeout, verify),
    }
    out = {"target": target_url, "error": base.get("error"),
           "baseline": base, "probes": probes}
    out["result"] = analyze(baseline_ms, probes, threshold_ms)
    return out
