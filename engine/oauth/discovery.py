from __future__ import annotations

import httpx

from ..config import load_engine
from ..contract import Capability, ScanResult
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


CAPABILITY = Capability(
    name="oauth_discovery",
    description="Fetch OIDC .well-known/openid-configuration.",
    category="auth",
    cost="low",
    destructive=False,
    idempotent=True,
)


WELL_KNOWN = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/oauth2",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
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


def fetch(base_url, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()
    base = base_url.rstrip("/")
    for path in WELL_KNOWN:
        url = base + path
        viol = _roe_block(roe_guard, url, "GET")
        if viol:
            return {"error": f"ROE_BLOCK: {viol}"}
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=True) as c:
                r = c.get(url, headers=headers or {})
            if r.status_code == 200:
                data = r.json()
                if "issuer" in data or "authorization_endpoint" in data:
                    return {"url": url, "config": data}
        except Exception:
            continue
    return None


def scan(base_url, headers=None, roe_guard=None, timeout=8):
    out = fetch(base_url, headers=headers, roe_guard=roe_guard,
                timeout=timeout)
    if out is None:
        return ScanResult(
            capability="oauth_discovery", target=base_url,
            verdict="UNKNOWN",
            reason="no OIDC discovery document found",
        )
    if isinstance(out, dict) and out.get("error"):
        return ScanResult(
            capability="oauth_discovery", target=base_url,
            verdict="UNKNOWN", reason=out["error"],
        )
    cfg = out["config"]
    return ScanResult(
        capability="oauth_discovery", target=base_url,
        verdict="PASS", severity="info",
        reason=f"OIDC config: issuer={cfg.get('issuer')}",
        evidence={"url": out["url"], "config": cfg},
    )


__all__ = ["fetch", "scan", "CAPABILITY"]
