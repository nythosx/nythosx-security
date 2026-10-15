"""Cloud storage enumeration.

Derives candidate bucket names from a domain (base, base-backup, base-prod,
etc.), then probes S3 / GCS / Azure endpoints. Classifies each response:

  * public  — 200 with a listing body (severe)
  * private — 403, bucket exists but not readable
  * available — 404 NoSuchBucket → anyone can register it
  * exists  — 200 with non-listing body (default page)
  * unknown — other response

The bucket endpoints are third-party services, NOT the scan target.
ROE does not apply here (same exception class as engine/sca.py and
engine/cve_lookup.py).
"""
from __future__ import annotations

from urllib.parse import urlparse

import httpx

from .config import load_engine
from .contract import Capability, ScanResult


CAPABILITY = Capability(
    name="cloud_storage_enum",
    description=("Enumerate cloud storage buckets derived from a domain "
                 "and classify each as public / private / available."),
    category="recon",
    cost="medium",
    destructive=False,
    idempotent=True,
)


BASE_SUFFIXES = [
    "",
    "-backup", "-backups",
    "-prod", "-production",
    "-dev", "-development",
    "-staging", "-stage", "-test",
    "-assets", "-static", "-media",
    "-uploads", "-files", "-images",
    "-logs", "-data", "-dump", "-dumps",
    "-public", "-private",
    "-cdn", "-web", "-app",
]


DEFAULT_ENDPOINTS = [
    {"provider": "s3",    "url_template": "https://{bucket}.s3.amazonaws.com/"},
    {"provider": "s3",    "url_template": "https://s3.amazonaws.com/{bucket}/"},
    {"provider": "gcs",   "url_template": "https://storage.googleapis.com/{bucket}/"},
    {"provider": "azure", "url_template": "https://{bucket}.blob.core.windows.net/"},
]


AVAILABLE_MARKERS = [
    "nosuchbucket", "the specified bucket does not exist",
    "no such bucket",
]

PUBLIC_LISTING_MARKERS = [
    "<listbucketresult",
    "<contents>",
    "<key>",
    '"items":',
]


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


_COMPOUND_SUFFIXES = frozenset([
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "ac.uk", "gov.uk", "mod.uk", "nhs.uk", "police.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ad.jp", "ed.jp", "gr.jp",
    "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph", "ngo.ph", "mil.ph",
    "co.in", "net.in", "org.in", "gen.in", "ind.in", "ac.in", "edu.in",
    "gov.in", "mil.in", "res.in", "firm.in",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    "co.kr", "ne.kr", "or.kr", "re.kr", "go.kr", "ac.kr",
    "co.za", "net.za", "org.za", "gov.za", "ac.za", "edu.za", "web.za",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "per.sg",
    "co.id", "net.id", "or.id", "web.id", "ac.id", "sch.id", "go.id",
    "mil.id", "my.id", "biz.id",
    "co.th", "in.th", "ac.th", "go.th", "or.th", "net.th",
    "com.my", "net.my", "org.my", "gov.my", "edu.my", "mil.my",
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "bel.tr", "k12.tr",
    "com.hk", "edu.hk", "gov.hk", "org.hk", "net.hk",
    "com.tw", "edu.tw", "gov.tw", "org.tw", "net.tw",
    "co.il", "org.il", "ac.il", "gov.il", "net.il",
    "com.ar", "gov.ar", "edu.ar", "org.ar", "net.ar",
    "com.co", "edu.co", "gov.co", "org.co", "net.co",
    "co.ke", "or.ke", "ac.ke", "go.ke",
    "com.ng", "org.ng", "gov.ng", "edu.ng", "net.ng",
    "com.pk", "edu.pk", "gov.pk", "org.pk", "net.pk",
    "com.vn", "edu.vn", "gov.vn", "net.vn", "org.vn",
    "com.sa", "edu.sa", "gov.sa", "org.sa", "net.sa",
    "com.eg", "edu.eg", "gov.eg", "org.eg", "net.eg",
])


def _base_name(domain):
    if "://" in domain:
        domain = urlparse(domain).hostname or domain
    parts = [p for p in domain.split(".") if p]
    if not parts:
        return ""
    if len(parts) >= 3 and (parts[-2] + "." + parts[-1]) in _COMPOUND_SUFFIXES:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def candidate_buckets(domain):
    base = _base_name(domain)
    if not base:
        return []
    out = []
    for suffix in BASE_SUFFIXES:
        out.append(base + suffix)
    seen = set()
    result = []
    for b in out:
        if b and b not in seen:
            seen.add(b)
            result.append(b)
    return result


def classify(status, body):
    if status is None:
        return "unreachable"
    low = (body or "").lower()
    if status == 404:
        if any(m in low for m in AVAILABLE_MARKERS):
            return "available"
        return "not_found"
    if status in (401, 403):
        return "private"
    if status == 200:
        if any(m in low for m in PUBLIC_LISTING_MARKERS):
            return "public"
        return "exists"
    return "unknown"


def _probe(url, timeout, verify):
    try:
        with httpx.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(url)
        return {"url": url, "status": r.status_code,
                "body": (r.text or "")[:10000]}
    except httpx.ConnectError as e:
        return {"url": url, "status": None,
                "error": f"connection error: {e}"}
    except httpx.TimeoutException:
        return {"url": url, "status": None, "error": "timeout"}
    except Exception as e:
        return {"url": url, "status": None,
                "error": f"{type(e).__name__}: {e}"}


async def scan_async(domain, timeout=8, endpoints=None, max_buckets=None):
    import asyncio
    import httpx
    verify = _verify_tls()
    buckets = candidate_buckets(domain)
    if max_buckets:
        buckets = buckets[:max_buckets]
    if not buckets:
        return ScanResult(
            capability="cloud_storage_enum", target=domain,
            verdict="UNKNOWN", reason="could not derive bucket names",
        )
    eps = endpoints or DEFAULT_ENDPOINTS
    results = []
    sem = asyncio.Semaphore(20)

    async def _one(client, bucket, ep):
        async with sem:
            url = ep["url_template"].format(bucket=bucket, account=bucket)
            try:
                r = await client.get(url, follow_redirects=False)
            except Exception:
                return None
            classification = classify(r.status_code, r.text)
            if classification in ("not_found", "unreachable"):
                return None
            return {
                "bucket": bucket,
                "provider": ep["provider"],
                "url": url,
                "status": r.status_code,
                "classification": classification,
            }

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=verify,
                                      follow_redirects=False) as c:
            tasks = []
            for bucket in buckets:
                for ep in eps:
                    tasks.append(_one(c, bucket, ep))
            for r in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(r, dict):
                    results.append(r)
    except Exception as e:
        import sys as _sys
        _sys.stderr.write(
            f"[cloud_storage.scan_async] {type(e).__name__}: {e}\n")
    public = [r for r in results if r["classification"] == "public"]
    available = [r for r in results if r["classification"] == "available"]
    private = [r for r in results if r["classification"] == "private"]
    if public:
        return ScanResult(
            capability="cloud_storage_enum", target=domain,
            verdict="VULNERABLE", severity="high",
            reason=(f"{len(public)} publicly listable bucket(s): "
                    + ", ".join(r["bucket"] for r in public[:5])),
            evidence={"public": public, "available": available,
                      "private": private},
        )
    if available:
        return ScanResult(
            capability="cloud_storage_enum", target=domain,
            verdict="SUSPICIOUS", severity="medium",
            reason=(f"{len(available)} available bucket name(s) — a subdomain "
                    f"or application referencing them may be takeover-able: "
                    + ", ".join(r["bucket"] for r in available[:5])),
            evidence={"public": public, "available": available,
                      "private": private},
        )
    if private:
        return ScanResult(
            capability="cloud_storage_enum", target=domain,
            verdict="PASS", severity="low",
            reason=(f"{len(private)} private bucket(s), none public"),
            evidence={"private": private},
        )
    return ScanResult(
        capability="cloud_storage_enum", target=domain,
        verdict="PASS", severity="low",
        reason=f"no matching buckets across {len(buckets)} candidate(s)",
    )


def scan(domain, timeout=8, endpoints=None, max_buckets=None):
    from .http_async import run_sync
    return run_sync(scan_async(domain, timeout=timeout, endpoints=endpoints,
                                max_buckets=max_buckets))


__all__ = ["scan", "scan_async", "CAPABILITY", "candidate_buckets",
           "classify", "DEFAULT_ENDPOINTS"]
