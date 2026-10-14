"""Subdomain takeover detection.

Fetches each candidate URL, matches the response body against fingerprints
of known-vulnerable third-party services. Presence of the fingerprint means
the subdomain's CNAME still points at a service that no longer has a
resource at that name — anyone can register it and serve content.

The scanner fetches the TARGET subdomains, so ROE applies.
"""
from __future__ import annotations

from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


CAPABILITY = Capability(
    name="subdomain_takeover",
    description=("Detect subdomain takeover by matching response bodies "
                 "against known-vulnerable third-party service fingerprints."),
    category="recon",
    cost="low",
    destructive=False,
    idempotent=True,
)


FINGERPRINTS = [
    {"service": "heroku", "severity": "high",
     "body_contains": ["no such app", "heroku | no such app",
                       "<title>no such app</title>"]},
    {"service": "github_pages", "severity": "high",
     "body_contains": ["there isn't a github pages site here",
                       "for root urls (like http://example.com/)"]},
    {"service": "aws_s3", "severity": "high",
     "body_contains": ["nosuchbucket",
                       "the specified bucket does not exist"]},
    {"service": "azure", "severity": "high",
     "body_contains": ["404 web site not found",
                       "the page you are looking for is not found"]},
    {"service": "shopify", "severity": "medium",
     "body_contains": ["sorry, this shop is currently unavailable",
                       "only one moment"]},
    {"service": "tumblr", "severity": "medium",
     "body_contains": ["whatever you were looking for doesn't currently exist",
                       "there's nothing here."]},
    {"service": "bitbucket", "severity": "high",
     "body_contains": ["repository not found"]},
    {"service": "fastly", "severity": "medium",
     "body_contains": ["fastly error: unknown domain"]},
    {"service": "surge", "severity": "medium",
     "body_contains": ["project not found"]},
    {"service": "readthedocs", "severity": "medium",
     "body_contains": ["unknown to read the docs"]},
    {"service": "netlify", "severity": "medium",
     "body_contains": ["not found - request id"]},
    {"service": "vercel", "severity": "medium",
     "body_contains": ["the deployment could not be found on vercel"]},
    {"service": "ghost", "severity": "medium",
     "body_contains": ["the thing you were looking for is no longer here"]},
    {"service": "zendesk", "severity": "medium",
     "body_contains": ["help center closed"]},
    {"service": "pantheon", "severity": "medium",
     "body_contains": ["the gods are wise, but do not know of the site which you seek"]},
    {"service": "helpscout", "severity": "medium",
     "body_contains": ["no settings were found for this company"]},
    {"service": "teamwork", "severity": "medium",
     "body_contains": ["oops - we didn't find your site"]},
    {"service": "statuspage", "severity": "low",
     "body_contains": ["you are being redirected"]},
    {"service": "desk", "severity": "medium",
     "body_contains": ["sorry, we couldn't find that page"]},
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


def _fetch(url, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}", "url": url}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=True) as c:
            r = c.get(url)
        return {"url": url, "status": r.status_code,
                "body": (r.text or "")[:50000],
                "server": r.headers.get("Server", "")}
    except _http.ConnectError as e:
        return {"url": url, "status": None,
                "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"url": url, "status": None, "error": "timeout"}
    except Exception as e:
        return {"url": url, "status": None,
                "error": f"{type(e).__name__}: {e}"}


def _match_fingerprint(body):
    if not body:
        return None
    low = body.lower()
    for fp in FINGERPRINTS:
        for needle in fp.get("body_contains") or []:
            if needle.lower() in low:
                return fp
    return None


def scan(urls, roe_guard=None, timeout=8):
    if not urls:
        return ScanResult(
            capability="subdomain_takeover", target="(none)",
            verdict="UNKNOWN", reason="no URLs provided",
        )
    verify = _verify_tls()
    findings = []
    attempts = []
    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        r = _fetch(url, timeout, verify, roe_guard)
        if r.get("blocked"):
            return ScanResult(
                capability="subdomain_takeover", target=url,
                verdict="UNKNOWN", reason=r["error"],
            )
        attempts.append({"url": url, "status": r.get("status"),
                          "server": r.get("server", "")})
        if r.get("status") is None:
            continue
        fp = _match_fingerprint(r.get("body") or "")
        if fp:
            findings.append({
                "url": url,
                "service": fp["service"],
                "severity": fp["severity"],
                "status": r.get("status"),
                "preview": (r.get("body") or "")[:200],
            })
    if findings:
        services = sorted({f["service"] for f in findings})
        return ScanResult(
            capability="subdomain_takeover",
            target=findings[0]["url"],
            verdict="VULNERABLE", severity="high",
            reason=(f"{len(findings)} subdomain takeover candidate(s): "
                    + ", ".join(services)),
            evidence={"findings": findings, "attempts": attempts},
        )
    live = [a for a in attempts if a.get("status") is not None]
    if not live:
        return ScanResult(
            capability="subdomain_takeover", target=urls[0],
            verdict="UNKNOWN", reason="no URLs were reachable",
            evidence={"attempts": attempts},
        )
    return ScanResult(
        capability="subdomain_takeover", target=urls[0],
        verdict="PASS", severity="low",
        reason=(f"no takeover fingerprint across {len(live)} live host(s)"),
        evidence={"attempts": attempts},
    )


__all__ = ["scan", "CAPABILITY", "FINGERPRINTS"]
