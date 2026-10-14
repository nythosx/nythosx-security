from __future__ import annotations

import base64
import json
import pickle

import httpx

from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


CAPABILITY = Capability(
    name="deserialization_scan",
    description=("Detect unsafe deserialization: send magic-byte payloads to "
                 "reflection points, look for parser errors that prove the "
                 "endpoint passed bytes to a native deserializer."),
    category="injection",
    cost="medium",
    destructive=False,
    idempotent=True,
)


_JAVA_PAYLOAD = base64.b64encode(
    b"\xac\xed\x00\x05" + b"sec-checker-probe").decode("ascii")

_PYTHON_PAYLOAD = base64.b64encode(
    pickle.dumps({"sec_checker_probe": True}, protocol=2)).decode("ascii")

_PHP_PAYLOAD = 'O:8:"stdClass":1:{s:4:"probe";s:3:"yes";}'

_DOTNET_PAYLOAD = "AAEAAAD/////AQAAAAAAAAAMAgAAAJgBc2VjLWNoZWNrZXI="


VECTORS = [
    ("java_magic",      _JAVA_PAYLOAD,    "base64"),
    ("php_object",      _PHP_PAYLOAD,     "raw"),
    ("python_pickle",   _PYTHON_PAYLOAD,  "base64"),
    ("dotnet_binary",   _DOTNET_PAYLOAD,  "base64"),
]


SIGNATURES = {
    "java": [
        "java.io.InvalidClassException",
        "java.io.ObjectInputStream",
        "java.io.StreamCorruptedException",
        "java.lang.ClassNotFoundException",
        "java.lang.ClassCastException",
        "Cannot deserialize",
        "InvalidClassException",
    ],
    "php": [
        "unserialize()",
        "unserialization of",
        "cannot be unserialized",
        "unserialize(): Error",
        "Notice: unserialize",
        "Warning: unserialize",
        "__PHP_Incomplete_Class",
    ],
    "python": [
        "_pickle.UnpicklingError",
        "pickle.UnpicklingError",
        "invalid load key",
        "unpickling stack",
        "Could not unpickle",
        "EOFError: Ran out of input",
    ],
    "dotnet": [
        "BinaryFormatter",
        "System.Runtime.Serialization",
        "SerializationException",
        "Invalid binary format",
        "EndOfStreamException",
    ],
}


_INJECTION_LOCATIONS = [
    ("cookie", "session"),
    ("body", "_sc"),
    ("header", "X-Session"),
]


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


def _baseline(url, method, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.request(method.upper(), url, headers=headers or {})
        return {"status": r.status_code, "body": r.text or "",
                "content_type": r.headers.get("Content-Type", "")}
    except _http.ConnectError as e:
        return {"status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _send(url, method, headers, body, timeout, verify, roe_guard, as_json=False):
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if as_json:
                r = c.request(method.upper(), url, headers=headers or {},
                              json=body)
            else:
                r = c.request(method.upper(), url, headers=headers or {},
                              content=body)
        return {"status": r.status_code, "body": (r.text or "")[:8000],
                "content_type": r.headers.get("Content-Type", "")}
    except _http.ConnectError as e:
        return {"status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _detect_signature(body):
    if not body:
        return []
    hits = []
    low = body.lower()
    for lang, sigs in SIGNATURES.items():
        for s in sigs:
            if s.lower() in low:
                hits.append({"language": lang, "signature": s})
    return hits


def _inject(url, method, headers, payload, location, name, timeout,
            verify, roe_guard):
    base_headers = dict(headers or {})
    body = None
    as_json = False
    if location == "cookie":
        existing = base_headers.get("Cookie", "")
        sep = "; " if existing else ""
        base_headers["Cookie"] = f"{existing}{sep}{name}={payload}"
    elif location == "header":
        base_headers[name] = payload
    elif location == "body":
        body = json.dumps({name: payload})
        base_headers.setdefault("Content-Type", "application/json")
        as_json = True
    return _send(url, method, base_headers, body, timeout, verify, roe_guard,
                 as_json=as_json)


def scan(target_url, method="POST", headers=None, timeout=8, roe_guard=None):
    verify = _verify_tls()
    viol = _roe_block(roe_guard, target_url, method)
    if viol:
        return ScanResult(
            capability="deserialization_scan", target=target_url,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )
    baseline = _baseline(target_url, method, headers, timeout, verify, roe_guard)
    if baseline.get("blocked"):
        return ScanResult(
            capability="deserialization_scan", target=target_url,
            verdict="UNKNOWN", reason=baseline["error"],
        )
    base_sigs = _detect_signature(baseline.get("body") or "")

    findings = []
    attempts = []
    for vector_name, payload, kind in VECTORS:
        for location, name in _INJECTION_LOCATIONS:
            r = _inject(target_url, method, headers, payload, location, name,
                        timeout, verify, roe_guard)
            if r.get("blocked"):
                return ScanResult(
                    capability="deserialization_scan", target=target_url,
                    verdict="UNKNOWN", reason=r["error"],
                )
            entry = {"vector": vector_name, "location": location,
                     "name": name, "status": r.get("status")}
            attempts.append(entry)
            if r.get("status") is None:
                continue
            sigs = _detect_signature(r.get("body") or "")
            new_sigs = [s for s in sigs if s not in base_sigs]
            if new_sigs:
                findings.append({
                    "vector": vector_name,
                    "location": location,
                    "name": name,
                    "status": r.get("status"),
                    "signatures": new_sigs,
                    "preview": (r.get("body") or "")[:300],
                })
                break
        if findings:
            break

    if findings:
        first = findings[0]
        langs = {s["language"] for s in first["signatures"]}
        return ScanResult(
            capability="deserialization_scan", target=target_url,
            verdict="VULNERABLE", severity="critical",
            reason=(f"{'/'.join(sorted(langs))} deserializer consumed payload "
                    f"at {first['location']}:{first['name']} — "
                    f"parser error surfaced in response"),
            evidence={"findings": findings, "attempts": attempts},
        )

    live = [a for a in attempts if a.get("status") is not None]
    if not live:
        return ScanResult(
            capability="deserialization_scan", target=target_url,
            verdict="UNKNOWN", reason="all probes failed",
            evidence={"attempts": attempts},
        )
    return ScanResult(
        capability="deserialization_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"no deserialization error signatures across {len(live)} probes",
        evidence={"attempts": attempts},
    )


__all__ = ["scan", "CAPABILITY", "SIGNATURES"]
