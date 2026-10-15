"""NVD CPE lookup for detected component versions.

Offline-safe: if NVD is unreachable or the product/version does not map to a
known CPE, returns an empty list. Never raises on network failure. The caller
(recon) decides how to surface hits.

Target-side discipline: NVD is an external vulnerability database, not a
scan target, so ROE does not apply here. See sec_checker_tools/registry for
the same exception pattern used by sca.py.
"""
import os
import re
from functools import lru_cache

import httpx

from .config import load_engine


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CPE_MAP = {
    "nginx": ("nginx", "nginx"),
    "nginx_plus": ("nginx", "nginx_plus"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "php": ("php", "php"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "laravel": ("laravel", "laravel"),
    "django": ("djangoproject", "django"),
    "rails": ("rubyonrails", "rails"),
    "ruby_on_rails": ("rubyonrails", "rails"),
    "spring": ("vmware", "spring_framework"),
    "spring_framework": ("vmware", "spring_framework"),
    "spring_boot": ("vmware", "spring_boot"),
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    "wildfly": ("redhat", "wildfly"),
    "node": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    "express": ("expressjs", "express"),
    "fastapi": ("tiangolo", "fastapi"),
    "haproxy": ("haproxy", "haproxy"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "varnish": ("varnish-software", "varnish_cache"),
    "squid": ("squid-cache", "squid"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "grafana": ("grafana", "grafana"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
    "phppgadmin": ("phppgadmin", "phppgadmin"),
    "adminer": ("adminer", "adminer"),
}

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+){0,3})")


def _cfg():
    try:
        cfg = load_engine() or {}
        return cfg.get("cve_lookup") or {}
    except Exception:
        return {}


def _normalize_version(version):
    if not version:
        return ""
    m = _VERSION_RE.match(str(version).strip())
    return m.group(1) if m else ""


def _normalize_product(product):
    if not product:
        return ""
    p = str(product).strip().lower()
    p = re.sub(r"[^a-z0-9]+", "_", p).strip("_")
    return p


def _api_key(cfg):
    env_name = cfg.get("nvd_api_key_env") or "NVD_API_KEY"
    return os.environ.get(env_name) or None


def _severity_from_metrics(metrics):
    from .cvss import cvss_vector_to_score, score_to_severity
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr:
            continue
        data = (arr[0].get("cvssData") or {})
        sev = data.get("baseSeverity") or arr[0].get("baseSeverity")
        if sev:
            return str(sev).lower()
        vector = data.get("vectorString") or ""
        score = cvss_vector_to_score(vector)
        if score is not None:
            return score_to_severity(score)
    return "medium"


@lru_cache(maxsize=512)
def _lookup_cached(vendor, product, version, api_key, timeout):
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        with httpx.Client(timeout=timeout, headers=headers) as c:
            r = c.get(NVD_API, params={"cpeName": cpe})
        if r.status_code != 200:
            return ()
        data = r.json()
    except Exception:
        return ()
    out = []
    for entry in (data.get("vulnerabilities") or []):
        c = entry.get("cve") or {}
        cid = c.get("id")
        if not cid:
            continue
        descs = c.get("descriptions") or []
        summary = next((d.get("value", "") for d in descs
                        if d.get("lang") == "en"), "")[:280]
        out.append({
            "id": cid,
            "severity": _severity_from_metrics(c.get("metrics") or {}),
            "summary": summary,
            "published": c.get("published", ""),
        })
    return tuple(out)


def lookup(product, version):
    cfg = _cfg()
    if cfg.get("enabled") is False:
        return []
    product_key = _normalize_product(product)
    version = _normalize_version(version)
    if not product_key or not version:
        return []
    overrides = cfg.get("cpe_overrides") or {}
    if product_key in overrides:
        pair = overrides[product_key]
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            vendor, prod = pair
        else:
            return []
    elif product_key in CPE_MAP:
        vendor, prod = CPE_MAP[product_key]
    else:
        return []
    timeout = float(cfg.get("timeout_seconds") or 15)
    max_results = int(cfg.get("max_results_per_product") or 25)
    hits = _lookup_cached(vendor, prod, version,
                          _api_key(cfg) or "", timeout)
    return list(hits[:max_results])


def summarize(hits):
    if not hits:
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    counts = {"total": len(hits), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for h in hits:
        sev = h.get("severity") or "medium"
        if sev in counts:
            counts[sev] += 1
    return counts


__all__ = ["lookup", "summarize", "CPE_MAP"]
