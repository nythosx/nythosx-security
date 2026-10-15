from __future__ import annotations

import io
import uuid

import httpx

from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http
from .util import any_handler_reached, unreached_reason


CAPABILITY = Capability(
    name="upload_scan",
    description=("File upload restriction testing: extension bypass, magic "
                 "bytes, path traversal, polyglot. Destructive — writes files."),
    category="injection",
    cost="high",
    destructive=True,
    idempotent=False,
    prerequisites=["written_authorization"],
    default_on=False,
)


PHP_PAYLOAD = b"<?php echo 'SEC_CHECKER_UPLOAD_PROBE'; ?>"
SVG_XSS_PAYLOAD = (b'<?xml version="1.0" standalone="no"?>'
                    b'<svg xmlns="http://www.w3.org/2000/svg">'
                    b'<script>alert("SEC_CHECKER_UPLOAD")</script></svg>')
JPEG_PHP_POLYGLOT = (b"\xff\xd8\xff\xe0" + b"A" * 100 + PHP_PAYLOAD)


UPLOAD_VARIANTS = [
    ("plain_php", "probe.php", "application/x-php", PHP_PAYLOAD),
    ("double_ext", "probe.php.jpg", "image/jpeg", PHP_PAYLOAD),
    ("null_byte", "probe.php\x00.jpg", "image/jpeg", PHP_PAYLOAD),
    ("case_php", "probe.PHP", "application/x-php", PHP_PAYLOAD),
    ("phtml", "probe.phtml", "application/x-php", PHP_PAYLOAD),
    ("php5", "probe.php5", "application/x-php", PHP_PAYLOAD),
    ("php7", "probe.php7", "application/x-php", PHP_PAYLOAD),
    ("svg_xss", "probe.svg", "image/svg+xml", SVG_XSS_PAYLOAD),
    ("jpeg_polyglot", "probe.jpg", "image/jpeg", JPEG_PHP_POLYGLOT),
    ("traversal", "../../../../tmp/sc_probe.txt", "text/plain",
     b"SEC_CHECKER_TRAVERSAL"),
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


def _upload(url, filename, content_type, content, field, headers, timeout,
             verify, roe_guard):
    viol = _roe_block(roe_guard, url, "POST")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    files = {field: (filename, io.BytesIO(content), content_type)}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(url, files=files, headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:2000],
                "location": r.headers.get("Location", "")[:200]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _looks_accepted(resp):
    if not resp or resp.get("status") is None:
        return False
    if resp["status"] in (401, 403, 415, 422):
        return False
    if resp["status"] not in (200, 201, 202, 204):
        return False
    body = (resp.get("body") or "").lower()
    if any(m in body for m in ("invalid", "not allowed", "forbidden",
                                "reject", "bad extension", "unsupported")):
        return False
    return True


def scan(upload_url, headers=None, roe_guard=None, timeout=15,
         field_name="file"):
    verify = _verify_tls()
    cfg = (load_engine() or {}).get("upload") or {}
    if not cfg.get("opt_in", False):
        return ScanResult(
            capability="upload_scan", target=upload_url,
            verdict="UNKNOWN",
            reason=("destructive upload probe disabled (set "
                    "upload.opt_in: true in engine.yaml)"),
        )

    attempts = []
    findings = []
    for label, filename, ctype, content in UPLOAD_VARIANTS:
        r = _upload(upload_url, filename, ctype, content, field_name,
                    headers, timeout, verify, roe_guard)
        if r.get("blocked"):
            return ScanResult(
                capability="upload_scan", target=upload_url,
                verdict="UNKNOWN", reason=r["error"],
            )
        attempts.append({"variant": label, "status": r.get("status")})
        if _looks_accepted(r):
            findings.append({"variant": label, "filename": filename,
                             "content_type": ctype})

    dangerous = [f for f in findings
                 if any(k in f["variant"] for k in
                        ("plain_php", "double_ext", "case_php", "phtml",
                         "php5", "php7", "null_byte"))]
    svg = [f for f in findings if f["variant"] == "svg_xss"]
    traversal = [f for f in findings if f["variant"] == "traversal"]

    if dangerous or traversal:
        return ScanResult(
            capability="upload_scan", target=upload_url,
            verdict="VULNERABLE", severity="critical",
            reason=(f"upload accepted dangerous variant "
                    f"'{findings[0]['variant']}'"),
            evidence={"findings": findings, "attempts": attempts},
        )
    if svg:
        return ScanResult(
            capability="upload_scan", target=upload_url,
            verdict="SUSPICIOUS", severity="medium",
            reason="SVG upload accepted (potential stored XSS)",
            evidence={"findings": findings, "attempts": attempts},
        )
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="upload_scan", target=upload_url,
            verdict="UNKNOWN",
            reason=unreached_reason(attempts),
            evidence={"attempts": attempts[:30]},
        )
    return ScanResult(
        capability="upload_scan", target=upload_url,
        verdict="PASS", severity="low",
        reason=f"no dangerous upload accepted across {len(attempts)} variants",
    )


__all__ = ["scan", "CAPABILITY"]
