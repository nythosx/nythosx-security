from __future__ import annotations

import re

from .chain_engine import register_tool
from .config import load_engine
from . import http as _http

_PATHS = ["/.npmrc", "/.pypirc", "/.gem/credentials", "/auth.json",
           "/.docker/config.json", "/.netrc"]

_CRED_PATTERNS = [
    r"_authToken\s*=\s*\S+",
    r"_auth\s*=\s*\S+",
    r"password\s*[:=]\s*\S+",
    r"username\s*[:=]\s*\S+",
    r"pypi-[A-Za-z0-9_\-]{20,}",
    r"gem-[A-Za-z0-9_\-]{20,}",
    r'"auth"\s*:\s*"[^"]+"',
    r"Bearer\s+[A-Za-z0-9\-_.]{16,}",
    r"Basic\s+[A-Za-z0-9+/=]{16,}",
]


def _verify_tls():
    try:
        return bool((load_engine() or {}).get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _tool_npmrc_probe(orch, args):
    url = (args.get("url") or orch.target).rstrip("/")
    verify = _verify_tls()
    hits = []
    attempts = []
    
    # Fetch soft-404 baseline to ignore catch-all pages
    neg_fp = getattr(orch, "_negative_baseline", None)
    
    for path in _PATHS:
        try:
            with _http.Client(timeout=8, verify=verify,
                              follow_redirects=False) as c:
                r = c.get(url + path)
        except Exception as e:
            attempts.append({"path": path, "error": f"{type(e).__name__}: {e}"})
            continue
        attempts.append({"path": path, "status": r.status_code})
        
        # Skip if this is a catch-all page (soft-404)
        if neg_fp and neg_fp.get("catch_all"):
            body = r.text or ""
            ct = r.headers.get("Content-Type", "").lower()
            is_html = "text/html" in ct
            size = len(body)
            nsize = neg_fp.get("size") or 0
            status = r.status_code
            
            if status == neg_fp.get("status") and is_html and neg_fp.get("is_html"):
                if not nsize or abs(size - nsize) <= max(80, int(nsize * 0.15)):
                    continue  # It's a catch-all page, skip!

        if r.status_code != 200:
            continue
        body = r.text or ""
        matched = []
        for pat in _CRED_PATTERNS:
            try:
                for m in re.finditer(pat, body):
                    matched.append(m.group(0)[:60])
            except re.error:
                continue
        if matched:
            hits.append({"path": path, "matched": matched[:5],
                         "preview": body[:300]})
    if hits:
        return {"verdict": "VULNERABLE",
                "reason": f"{len(hits)} package-manager config file(s) exposed",
                "evidence": {"hits": hits, "attempts": attempts}}
    return {"verdict": "PASS",
            "reason": f"no package-manager credential exposure across "
                      f"{len(_PATHS)} paths",
            "evidence": {"attempts": attempts}}


register_tool("npmrc_probe", _tool_npmrc_probe)
