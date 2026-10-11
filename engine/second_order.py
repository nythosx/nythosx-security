"""Second-order detection: track markers across endpoints.

After an injection point submits a unique marker, re-check other endpoints
that render user content to see if the marker propagated. Stored XSS,
stored SQLi, and similar classes show up here.
"""
import httpx

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


HTML_RENDER_HINTS = (
    "profile", "me", "account", "user", "users", "feed", "timeline",
    "dashboard", "comment", "post", "message", "notification",
    "admin", "setting", "search", "list", "detail", "view",
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


def candidate_endpoints(paths):
    """Filter paths that look like they render user content."""
    out = []
    for p in paths or []:
        pl = str(p).lower()
        if any(h in pl for h in HTML_RENDER_HINTS):
            out.append(p)
    return out


def _join(base, path):
    if path.startswith(("http://", "https://")):
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


def _fetch(url, headers, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return {"url": url, "blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=True) as c:
            r = c.get(url, headers=headers or {})
        return {"url": url, "status": r.status_code, "body": r.text or ""}
    except _http.ConnectError as e:
        return {"url": url, "status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"url": url, "status": None, "error": "timeout"}
    except Exception as e:
        return {"url": url, "status": None,
                "error": f"{type(e).__name__}: {e}"}


def check_propagation(base_url, endpoints, marker,
                       headers=None, cookies=None, roe_guard=None,
                       timeout=8, verify=None):
    """GET each endpoint, look for `marker`. Chain-engine result shape."""
    if verify is None:
        verify = _verify_tls()
    if not marker:
        return {"verdict": "UNKNOWN", "reason": "no marker provided",
                "evidence": {}}
    checked, hits, live = [], [], 0
    for path in endpoints:
        url = _join(base_url, path)
        r = _fetch(url, headers, timeout, verify, roe_guard)
        checked.append({"path": path, "status": r.get("status"),
                        "error": r.get("error")})
        if r.get("error") or r.get("status") is None:
            continue
        live += 1
        body = r.get("body") or ""
        if marker in body:
            idx = body.find(marker)
            hits.append({
                "path": path, "status": r.get("status"),
                "snippet": body[max(0, idx - 40): idx + 120],
            })
    evidence = {"marker": marker, "checked": checked, "hits": hits}
    if hits:
        return {
            "verdict": "VULNERABLE",
            "reason": (f"marker '{marker}' propagated to {len(hits)} "
                       f"endpoint(s) — stored / second-order injection "
                       f"confirmed"),
            "evidence": evidence,
        }
    if live == 0:
        return {"verdict": "UNKNOWN",
                "reason": "no reachable endpoints for second-order check",
                "evidence": evidence}
    return {"verdict": "PASS",
            "reason": f"marker not seen across {live} endpoint(s)",
            "evidence": evidence}


__all__ = ["check_propagation", "candidate_endpoints", "HTML_RENDER_HINTS"]
