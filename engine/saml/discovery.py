from __future__ import annotations

from urllib.parse import urlparse

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="saml_discovery",
    description="Locate SAML SSO / ACS endpoints on a target.",
    category="auth",
    cost="low",
    destructive=False,
    idempotent=True,
)

SSO_PATHS = [
    "/saml/login", "/saml/sso", "/sso/saml", "/auth/saml",
    "/adfs/ls", "/adfs/ls/idpinitiatedsignon.aspx", "/SAML/SSO",
    "/saml2/SSO", "/simplesaml/saml2/idp/SSOService.php",
]

ACS_PATHS = [
    "/saml/acs", "/saml/SSO", "/saml/consume", "/sso/saml/acs",
    "/auth/saml/callback", "/auth/saml/acs", "/SAML/AssertionConsumerService",
    "/adfs/ls", "/saml2/acs",
]

METADATA_PATHS = [
    "/saml/metadata", "/saml2/metadata", "/adfs/metadata",
    "/auth/saml/metadata",
]

SAML_MARKERS = ("saml", "SAMLResponse", "AssertionConsumerService",
                 "SingleSignOnService", "entityDescriptor")


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


def _probe(url, timeout, verify, roe_guard):
    if _roe_block(roe_guard, url, "GET"):
        return None
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(url)
        return {"status": r.status_code,
                "content_type": r.headers.get("Content-Type", "").lower(),
                "body": (r.text or "")[:8000]}
    except Exception:
        return None


def _looks_saml(resp):
    if not resp:
        return False
    body = (resp.get("body") or "").lower()
    if any(m.lower() in body for m in SAML_MARKERS):
        return True
    if resp.get("status") in (301, 302, 303):
        return True
    return False


def discover(base_url, timeout=10, roe_guard=None):
    verify = _verify_tls()
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    results = {"sso": [], "acs": [], "metadata": [], "saml_detected": False}
    for path in SSO_PATHS:
        url = origin + path
        resp = _probe(url, timeout, verify, roe_guard)
        if _looks_saml(resp):
            results["sso"].append({"url": url, "status": resp.get("status")})
            results["saml_detected"] = True
    for path in ACS_PATHS:
        url = origin + path
        resp = _probe(url, timeout, verify, roe_guard)
        if resp and resp.get("status") in (200, 400, 405):
            results["acs"].append({"url": url, "status": resp.get("status")})
            results["saml_detected"] = True
    for path in METADATA_PATHS:
        url = origin + path
        resp = _probe(url, timeout, verify, roe_guard)
        if resp and resp.get("status") == 200 and "xml" in resp.get("content_type", ""):
            results["metadata"].append({"url": url})
            results["saml_detected"] = True
    return results


def scan(base_url, timeout=10, roe_guard=None):
    disc = discover(base_url, timeout=timeout, roe_guard=roe_guard)
    if not disc["saml_detected"]:
        return ScanResult(
            capability="saml_discovery", target=base_url,
            verdict="PASS", severity="low",
            reason="no SAML endpoints detected",
        )
    return ScanResult(
        capability="saml_discovery", target=base_url,
        verdict="SUSPICIOUS", severity="info",
        reason=(f"SAML detected: {len(disc['sso'])} SSO, "
                f"{len(disc['acs'])} ACS, {len(disc['metadata'])} metadata endpoint(s) — "
                f"capture a SAMLResponse manually and run saml_xsw"),
        evidence=disc,
    )
