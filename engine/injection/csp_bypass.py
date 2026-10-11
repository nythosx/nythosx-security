from __future__ import annotations

import re
from urllib.parse import urlparse

from ..config import load_engine
from ..contract import Capability, make_result
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="csp_bypass_scan",
    description="Content-Security-Policy analysis: parse directives, enumerate bypass candidates.",
    category="injection",
    cost="low",
    destructive=False,
    idempotent=True,
)


JSONP_HINTS = ["jsonp", "callback=", "cb=", "json-callback", "/jq", "yui"]

COMMON_CDN_ALLOWLIST = [
    "cdn.jsdelivr.net", "ajax.googleapis.com", "cdnjs.cloudflare.com",
    "unpkg.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
]


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
            return f"ROE guard unavailable (fail-closed): {e}"
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def parse_csp(header_value):
    if not header_value:
        return {}
    directives = {}
    for part in header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        bits = part.split(None, 1)
        name = bits[0].lower()
        values = (bits[1].split() if len(bits) > 1 else [])
        directives[name] = values
    return directives


def analyze(directives, page_domain=""):
    if not directives:
        return []
    findings = []
    script_src = directives.get("script-src") or directives.get("default-src") or []
    script_src_lower = [s.lower() for s in script_src]

    if "'unsafe-inline'" in script_src_lower:
        if "'strict-dynamic'" not in script_src_lower and \
                not any(s.startswith("'nonce-") for s in script_src_lower) and \
                not any(s.startswith("'sha") for s in script_src_lower):
            findings.append({
                "issue": "unsafe-inline_without_strict_dynamic",
                "impact": "inline <script> and event handlers execute",
                "severity": "high",
            })

    if "'unsafe-eval'" in script_src_lower:
        findings.append({
            "issue": "unsafe-eval",
            "impact": "eval and Function constructor allowed",
            "severity": "high",
        })

    jsonp_hosts = []
    for src in script_src:
        s = src.strip("'\"")
        if s in ("'self'", "'none'", "*"):
            continue
        if any(hint in s.lower() for hint in JSONP_HINTS):
            jsonp_hosts.append(s)
        else:
            for cdn in COMMON_CDN_ALLOWLIST:
                if cdn in s:
                    jsonp_hosts.append(s)
    if jsonp_hosts:
        findings.append({
            "issue": "jsonp_capable_host",
            "impact": "script-src allows host that can serve attacker-controlled JS via JSONP callback",
            "severity": "high",
            "hosts": list(dict.fromkeys(jsonp_hosts))[:5],
        })

    if "base-uri" not in directives and "base-uri" not in directives:
        findings.append({
            "issue": "missing_base_uri",
            "impact": "<base> tag can be injected to redirect relative script loads",
            "severity": "medium",
        })

    if "form-action" not in directives:
        findings.append({
            "issue": "missing_form_action",
            "impact": "form can submit to attacker-controlled URL",
            "severity": "low",
        })

    if "*" in script_src:
        findings.append({
            "issue": "wildcard_script_src",
            "impact": "any origin can load scripts",
            "severity": "critical",
        })

    if "data:" in script_src_lower:
        findings.append({
            "issue": "data_uri_script_src",
            "impact": "attacker can serve JS via data: URL",
            "severity": "high",
        })

    return findings


def scan(target_url, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()
    viol = _roe_block(roe_guard, target_url, "GET")
    if viol:
        return make_result(
            {"verdict": "UNKNOWN", "reason": f"ROE_BLOCK: {viol}"},
            capability="csp_bypass_scan", args=(target_url,))

    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(target_url, headers=headers or {})
    except Exception as e:
        return make_result(
            {"verdict": "UNKNOWN",
             "reason": f"{type(e).__name__}: {e}"},
            capability="csp_bypass_scan", args=(target_url,))

    csp_header = ""
    for k, v in r.headers.items():
        if k.lower() == "content-security-policy":
            csp_header = v
            break

    if not csp_header:
        return make_result({
            "verdict": "VULNERABLE",
            "reason": "no Content-Security-Policy header present",
            "evidence": {"status": r.status_code},
        }, capability="csp_bypass_scan", args=(target_url,))

    directives = parse_csp(csp_header)
    host = urlparse(target_url).hostname or ""
    findings = analyze(directives, host)

    if findings:
        critical = [f for f in findings
                    if f["severity"] in ("critical", "high")]
        return make_result({
            "verdict": "VULNERABLE" if critical else "SUSPICIOUS",
            "reason": f"CSP has {len(findings)} weakness(es): "
                      + ", ".join(f["issue"] for f in findings[:3]),
            "evidence": {"csp": csp_header[:600], "findings": findings},
        }, capability="csp_bypass_scan", args=(target_url,))

    return make_result({
        "verdict": "PASS",
        "reason": "CSP directives do not present obvious bypass",
        "evidence": {"csp": csp_header[:600]},
    }, capability="csp_bypass_scan", args=(target_url,))


__all__ = ["scan", "parse_csp", "analyze", "CAPABILITY"]
