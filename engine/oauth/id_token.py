from __future__ import annotations

from ..contract import Capability, ScanResult
from ..config import load_engine
from ..roe_guard import ROEGuard, ROEViolation


CAPABILITY = Capability(
    name="oauth_id_token_scan",
    description="Reuse JWT attack suite against an OAuth id_token.",
    category="auth",
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


def scan(target_url, id_token, headers=None, method="GET", roe_guard=None):
    if not id_token:
        return ScanResult(
            capability="oauth_id_token_scan", target=target_url,
            verdict="UNKNOWN", reason="no id_token provided",
        )
    viol = _roe_block(roe_guard, target_url, method)
    if viol:
        return ScanResult(
            capability="oauth_id_token_scan", target=target_url,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )
    try:
        from .. import jwt_attacks
        out = jwt_attacks.run_attack_suite(
            target_url, id_token, method=method,
            headers=headers, roe_guard=roe_guard, verify=_verify_tls(),
        )
    except Exception as e:
        return ScanResult(
            capability="oauth_id_token_scan", target=target_url,
            verdict="UNKNOWN", reason=f"{type(e).__name__}: {e}",
        )
    if out.get("error"):
        return ScanResult(
            capability="oauth_id_token_scan", target=target_url,
            verdict="UNKNOWN", reason=out["error"],
        )
    results = out.get("results") or []
    counts = out.get("summary") or {}
    if counts.get("VULNERABLE"):
        vuln = [r for r in results if r.get("verdict") == "VULNERABLE"]
        return ScanResult(
            capability="oauth_id_token_scan", target=target_url,
            verdict="VULNERABLE", severity="critical",
            reason=f"JWT attack on id_token succeeded: {vuln[0]['vector']}",
            evidence={"results": results[:10], "summary": counts},
        )
    return ScanResult(
        capability="oauth_id_token_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=f"id_token withstood {len(results)} JWT attack vectors",
        evidence={"summary": counts},
    )


__all__ = ["scan", "CAPABILITY"]
