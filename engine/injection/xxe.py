from __future__ import annotations

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .payloads import (XXE_FILE_PAYLOADS, XXE_TEMPLATE_BASIC,
                        XXE_TEMPLATE_OOB)
from .. import http as _http
from ..util import any_handler_reached, unreached_reason


CAPABILITY = Capability(
    name="xxe_scan",
    description="XML External Entity injection (file read + OOB).",
    category="injection",
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


def _post_xml(url, xml, headers, timeout, verify, roe_guard,
              content_type="application/xml"):
    viol = _roe_block(roe_guard, url, "POST")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    h = dict(headers or {})
    h["Content-Type"] = content_type
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(url, content=xml.encode("utf-8"), headers=h)
        return {"status": r.status_code, "body": (r.text or "")[:8000]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def scan(target_url, headers=None, roe_guard=None, timeout=8,
         oob_url=None):
    verify = _verify_tls()
    attempts = []
    findings = []

    for path, marker, label in XXE_FILE_PAYLOADS:
        xml = XXE_TEMPLATE_BASIC.format(path=path)
        r = _post_xml(target_url, xml, headers, timeout, verify, roe_guard)
        if r.get("blocked"):
            return ScanResult(
                capability="xxe_scan", target=target_url,
                verdict="UNKNOWN", reason=r["error"],
            )
        attempts.append({"payload": label, "status": r.get("status"),
                         "error": r.get("error")})
        body = r.get("body") or ""
        if marker and marker in body:
            findings.append({"payload": label, "path": path,
                             "marker": marker})
            break
        if not marker and body and r.get("status") in (200, 201, 202):
            if "root:" not in body and "localhost" not in body:
                continue

    if not findings and oob_url:
        xml = XXE_TEMPLATE_OOB.format(oob=oob_url)
        r = _post_xml(target_url, xml, headers, timeout, verify, roe_guard)
        attempts.append({"payload": "oob", "status": r.get("status"),
                         "error": r.get("error")})

    if findings:
        return ScanResult(
            capability="xxe_scan", target=target_url,
            verdict="VULNERABLE", severity="critical",
            reason=f"XXE file read confirmed via {findings[0]['path']}",
            evidence={"findings": findings, "attempts": attempts},
        )
    if not any_handler_reached(attempts):
        return ScanResult(
            capability="xxe_scan", target=target_url,
            verdict="UNKNOWN",
            reason=unreached_reason(attempts),
            evidence={"attempts": attempts},
        )
    return ScanResult(
        capability="xxe_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"no XXE expansion across {len(attempts)} attempts",
    )


__all__ = ["scan", "CAPABILITY"]
