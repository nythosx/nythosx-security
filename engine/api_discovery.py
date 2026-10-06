import re
import json
from urllib.parse import urljoin, urlparse
import httpx


COMMON_API_PORTS = [
    3000, 3001, 3002, 4000, 4001, 5000, 5001, 5173, 5174,
    8000, 8001, 8080, 8081, 8443, 9000, 9001, 10000,
]


def _fetch(url, timeout=10, follow=True):
    try:
        with httpx.Client(timeout=timeout, follow_redirects=follow, verify=False) as c:
            return c.get(url)
    except Exception:
        return None


def _extract_config_from_html(html, patterns):
    found = []
    for pat in patterns or []:
        try:
            compiled = re.compile(pat)
        except Exception:
            continue
        for m in compiled.finditer(html):
            value = m.group(1) if m.groups() else m.group(0)
            if value and len(value) < 300:
                found.append({"pattern": pat, "value": value})
    return found


def _extract_from_json_script(html, script_id):
    pat = re.compile(
        r'<script[^>]+id="' + re.escape(script_id) + r'"[^>]*>(.*?)</script>',
        re.DOTALL,
    )
    m = pat.search(html)
    if not m:
        return None
    try:
        return json.loads(m.group(1).strip())
    except Exception:
        return None


def _find_urls_in_structure(obj, depth=0, max_depth=8):
    if depth > max_depth:
        return []
    results = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if isinstance(v, str) and v.startswith(("http://", "https://", "/")):
                if any(h in kl for h in ("api", "url", "base", "endpoint", "host")):
                    results.append({"key": k, "value": v})
            else:
                results.extend(_find_urls_in_structure(v, depth + 1, max_depth))
    elif isinstance(obj, list):
        for item in obj[:50]:
            results.extend(_find_urls_in_structure(item, depth + 1, max_depth))
    return results


def detect_api_base_from_runtime(url, adapter=None):
    r = _fetch(url)
    if r is None or r.status_code != 200:
        return None
    html = r.text or ""
    runtime_cfg = (adapter or {}).get("runtime_config", {}) or {}
    html_patterns = runtime_cfg.get("html_patterns") or [
        r'apiBase\s*[:=]\s*["\']([^"\']+)["\']',
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
        r'API_URL\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    hits = _extract_config_from_html(html, html_patterns)
    if hits:
        for h in hits:
            v = h["value"]
            if v.startswith(("http://", "https://")):
                return {"base": v.rstrip("/"), "source": "html_pattern", "raw": v}
            if v.startswith("/"):
                return {"base": urljoin(str(r.url), v).rstrip("/"),
                        "source": "html_pattern", "raw": v}

    script_ids = runtime_cfg.get("json_scripts") or ["__NUXT_DATA__", "__NEXT_DATA__"]
    for sid in script_ids:
        data = _extract_from_json_script(html, sid)
        if data is None:
            continue
        urls = _find_urls_in_structure(data)
        for entry in urls:
            v = entry.get("value", "")
            if isinstance(v, str) and v.startswith(("http://", "https://")):
                return {"base": v.rstrip("/"), "source": f"json:{sid}.{entry['key']}",
                        "raw": v}
    return None


def _is_json_response(r):
    if r is None:
        return False
    ct = r.headers.get("Content-Type", "").lower()
    if "application/json" in ct:
        return True
    body = (r.text or "").lstrip()
    if body.startswith(("{", "[")):
        try:
            json.loads(body)
            return True
        except Exception:
            return False
    return False


def port_scan(host, ports=None, timeout=2):
    ports = ports or COMMON_API_PORTS
    parsed = urlparse(host)
    hostname = parsed.hostname or "localhost"
    current_port = parsed.port or 80
    alive = []
    for port in ports:
        if port == current_port:
            continue
        probe_url = f"http://{hostname}:{port}/api"
        r = _fetch(probe_url, timeout=timeout, follow=False)
        if r is None:
            probe_url = f"http://{hostname}:{port}/"
            r = _fetch(probe_url, timeout=timeout, follow=False)
        if r is None:
            continue
        alive.append({
            "port": port,
            "url": probe_url,
            "status": r.status_code,
            "content_type": r.headers.get("Content-Type", ""),
            "server": r.headers.get("Server", ""),
            "powered_by": r.headers.get("X-Powered-By", ""),
            "json": _is_json_response(r),
            "size": len(r.text or ""),
        })
    alive.sort(key=lambda x: (not x["json"], x["port"]))
    return alive


def discover(base_url, adapter=None):
    result = {
        "frontend": base_url,
        "runtime_config": None,
        "port_scan": [],
        "candidate_api_base": None,
        "source": None,
        "adapter": (adapter or {}).get("id", "generic"),
    }
    runtime = detect_api_base_from_runtime(base_url, adapter)
    if runtime:
        result["runtime_config"] = runtime
        result["candidate_api_base"] = runtime["base"]
        result["source"] = f"runtime:{runtime['source']}"
        return result

    parsed = urlparse(base_url)
    host = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        host = f"{host}:{parsed.port}"

    adapter_ports = (adapter or {}).get("ports")
    alive = port_scan(host, ports=adapter_ports)
    if not alive:
        alive = port_scan(host)
    result["port_scan"] = alive

    for entry in alive:
        if entry["json"]:
            api_base = f"http://{parsed.hostname}:{entry['port']}/api"
            result["candidate_api_base"] = api_base
            result["source"] = f"portscan:{entry['port']}"
            return result
    for entry in alive:
        api_base = f"http://{parsed.hostname}:{entry['port']}/api"
        result["candidate_api_base"] = api_base
        result["source"] = f"portscan:{entry['port']}"
        return result
    return result
