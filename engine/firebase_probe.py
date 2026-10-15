from __future__ import annotations

from urllib.parse import urlparse

import httpx

from .chain_engine import register_tool
from .config import load_engine


def _verify_tls():
    try:
        return bool((load_engine() or {}).get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _firebase_candidates(target):
    host = urlparse(target).hostname or target
    parts = host.split(".")
    out = []
    if len(parts) >= 2:
        base = parts[-2]
        out.append(f"https://{base}.firebaseio.com/.json")
        out.append(f"https://{base}-default-rtdb.firebaseio.com/.json")
        out.append(f"https://{base}.firebaseapp.com/__/firebase/init.json")
    return out


def _tool_firebase_probe(orch, args):
    target = args.get("url") or orch.target
    verify = _verify_tls()
    hits = []
    attempts = []
    for candidate in _firebase_candidates(target):
        try:
            with httpx.Client(timeout=8, verify=verify,
                              follow_redirects=False) as c:
                r = c.get(candidate)
        except Exception as e:
            attempts.append({"url": candidate,
                             "error": f"{type(e).__name__}: {e}"})
            continue
        attempts.append({"url": candidate, "status": r.status_code})
        if r.status_code != 200:
            continue
        body = (r.text or "").strip()
        if body.startswith("{") and len(body) > 4 and body != "{}":
            hits.append({"url": candidate, "preview": body[:300]})
    if hits:
        return {"verdict": "VULNERABLE",
                "reason": f"{len(hits)} Firebase endpoint(s) return data "
                          f"unauthenticated",
                "evidence": {"hits": hits, "attempts": attempts}}
    return {"verdict": "PASS",
            "reason": "no unauthenticated Firebase data exposure",
            "evidence": {"attempts": attempts}}


register_tool("firebase_probe", _tool_firebase_probe)
