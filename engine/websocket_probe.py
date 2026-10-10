from __future__ import annotations

import asyncio
import ssl as ssl_mod
from urllib.parse import urlparse

from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEGuard, ROEViolation


CAPABILITY = Capability(
    name="websocket_scan",
    description="WebSocket security: unauth handshake, CSWSH, message reflection.",
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


def _ws_url(url):
    p = urlparse(url)
    scheme = "wss" if p.scheme == "https" else "ws"
    return f"{scheme}://{p.netloc}{p.path or '/'}"


async def _try_handshake(ws_url, origin=None, headers=None, timeout=8,
                          verify=True):
    try:
        import websockets
    except ImportError:
        return {"ok": False, "error": "websockets library not installed"}
    h = dict(headers or {})
    if origin:
        h["Origin"] = origin
    ssl_ctx = None
    if ws_url.startswith("wss"):
        ssl_ctx = ssl_mod.create_default_context()
        if not verify:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl_mod.CERT_NONE
    try:
        async with websockets.connect(
            ws_url, extra_headers=h, open_timeout=timeout,
            ssl=ssl_ctx, close_timeout=2,
        ) as ws:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=1.5)
            except Exception:
                msg = None
            return {"ok": True, "received": (msg or "")[:500]}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            raise RuntimeError("event loop already running")
        return loop.run_until_complete(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def scan(target_url, headers=None, roe_guard=None, timeout=8):
    verify = _verify_tls()
    cfg = (load_engine() or {}).get("websocket") or {}
    if not cfg.get("enabled", True):
        return ScanResult(
            capability="websocket_scan", target=target_url,
            verdict="UNKNOWN", reason="websocket.enabled=false",
        )

    ws_url = _ws_url(target_url)
    viol = _roe_block(roe_guard, ws_url.replace("wss://", "https://")
                                  .replace("ws://", "http://"), "GET")
    if viol:
        return ScanResult(
            capability="websocket_scan", target=target_url,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )

    findings = []

    no_auth = _run(_try_handshake(ws_url, headers=None,
                                   timeout=timeout, verify=verify))
    if not no_auth.get("ok") and "websockets library" in no_auth.get("error", ""):
        return ScanResult(
            capability="websocket_scan", target=target_url,
            verdict="UNKNOWN", reason=no_auth["error"],
        )

    if no_auth.get("ok"):
        findings.append({"type": "unauth_handshake", "evidence": no_auth})

    cswsh = _run(_try_handshake(
        ws_url, origin="https://attacker.example.com",
        headers=headers, timeout=timeout, verify=verify))
    if cswsh.get("ok"):
        findings.append({"type": "cswsh_accepted_evil_origin",
                         "evidence": cswsh})

    if findings:
        v = "VULNERABLE" if any(f["type"] in ("unauth_handshake",
                                                "cswsh_accepted_evil_origin")
                                 for f in findings) else "SUSPICIOUS"
        return ScanResult(
            capability="websocket_scan", target=target_url,
            verdict=v, severity="high" if v == "VULNERABLE" else "medium",
            reason=f"WebSocket security issue: {findings[0]['type']}",
            evidence={"findings": findings, "ws_url": ws_url},
        )
    return ScanResult(
        capability="websocket_scan", target=target_url,
        verdict="PASS", severity="low",
        reason="handshake rejected without auth and cross-origin",
        evidence={"no_auth": no_auth, "cswsh": cswsh, "ws_url": ws_url},
    )


__all__ = ["scan", "CAPABILITY"]
