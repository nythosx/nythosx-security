"""Certificate Transparency log subdomain discovery.

Queries crt.sh (public, free, no auth) for every certificate ever issued
for a domain. Each certificate lists Subject Alternative Names, which
enumerate subdomains the certificate covered. This is passive recon:
we query crt.sh, not the target, so ROE scope does not apply to the
query itself.

An optional DNS resolution step can verify which subdomains still resolve.
DNS lookups are local (no target traffic), so also not ROE-gated.
"""
from __future__ import annotations

import json
import re
import socket

import httpx

from ..config import load_engine


CRT_SH_ENDPOINT = "https://crt.sh/"

_WILDCARD_RE = re.compile(r"^\*\.")


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _cfg():
    try:
        cfg = load_engine() or {}
        return cfg.get("ct_logs") or {}
    except Exception:
        return {}


def query_crt_sh(domain, timeout=25):
    try:
        with httpx.Client(timeout=timeout, verify=_verify_tls()) as c:
            r = c.get(CRT_SH_ENDPOINT, params={
                "q": f"%25.{domain}",
                "output": "json",
                "exclude": "expired",
            })
        if r.status_code != 200:
            return None
    except Exception:
        return None
    text = (r.text or "").strip()
    if not text or text[0] != "[":
        return None
    try:
        rows = json.loads(text)
    except Exception:
        return None

    names = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        nv = row.get("name_value") or ""
        for name in str(nv).split("\n"):
            name = name.strip().lower()
            if not name or name == domain or not name.endswith(domain):
                continue
            if _WILDCARD_RE.match(name):
                name = _WILDCARD_RE.sub("", name)
            if name.endswith("." + domain) or name == domain:
                if name != domain:
                    names.add(name)
    return sorted(names)


def resolve_subdomains(subdomains, timeout=1.5):
    live = []
    dead = []
    for sub in subdomains:
        try:
            socket.setdefaulttimeout(timeout)
            info = socket.getaddrinfo(sub, None)
            addrs = sorted({i[4][0] for i in info})
            live.append({"name": sub, "addrs": addrs})
        except Exception:
            dead.append(sub)
    return {"live": live, "dead": dead}


def harvest(domain, resolve=True, max_resolve=100, timeout=25):
    cfg = _cfg()
    if cfg.get("enabled") is False:
        return None
    if isinstance(domain, str) and "://" in domain:
        from urllib.parse import urlparse
        domain = urlparse(domain).hostname or domain

    subdomains = query_crt_sh(domain, timeout=timeout)
    if subdomains is None:
        return None
    out = {"domain": domain, "count": len(subdomains),
            "subdomains": subdomains}
    if resolve and subdomains:
        res = resolve_subdomains(subdomains[:max_resolve])
        out["live"] = res["live"]
        out["dead_count"] = len(res["dead"])
    return out


__all__ = ["query_crt_sh", "resolve_subdomains", "harvest"]
