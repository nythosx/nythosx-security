import re
from urllib.parse import urljoin
import httpx
from . import adapter_loader
from . import http as _http


def _fetch(url, timeout=10):
    try:
        with _http.Client(timeout=timeout, follow_redirects=True, verify=False) as c:
            return c.get(url)
    except Exception:
        return None


def _collect_observations(url):
    r = _fetch(url)
    if r is None:
        return None
    obs = {
        "url": str(r.url),
        "status": r.status_code,
        "headers": {k.lower(): v for k, v in r.headers.items()},
        "cookies": {},
        "html": (r.text or "")[:500000],
        "meta": {},
    }
    for k, v in r.cookies.items():
        obs["cookies"][k] = v
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(obs["html"], "lxml")
        for m in soup.find_all("meta"):
            name = (m.get("name") or m.get("property") or "").lower()
            content = m.get("content") or ""
            if name:
                obs["meta"][name] = content
    except Exception:
        pass
    return obs


def _header_match(headers, patterns):
    score = 0
    evidence = []
    if not patterns:
        return 0, []
    for header_name, expected_list in patterns.items():
        actual = headers.get(header_name.lower(), "")
        if not actual:
            continue
        for pattern in expected_list:
            if re.search(pattern, actual, re.IGNORECASE):
                score += 50
                evidence.append(f"header {header_name}={actual[:40]} matches {pattern}")
                break
    return score, evidence


def _cookie_match(cookies, expected_list):
    score = 0
    evidence = []
    for pattern in (expected_list or []):
        for name in cookies.keys():
            if re.search(pattern, name, re.IGNORECASE):
                score += 30
                evidence.append(f"cookie {name} matches {pattern}")
                break
    return score, evidence


def _html_match(html, needles):
    score = 0
    evidence = []
    for n in (needles or []):
        if n.lower() in html.lower():
            score += 20
            evidence.append(f"html contains '{n}'")
    return score, evidence


def _meta_match(meta, expected):
    if not expected:
        return 0, []
    actual = meta.get(expected.lower(), "")
    if actual and expected.lower() in actual.lower():
        return 25, [f"meta {expected}={actual[:40]}"]
    return 0, []


def _path_markers(url, markers):
    score = 0
    evidence = []
    for m in (markers or []):
        if m.lower() in url.lower():
            score += 10
            evidence.append(f"url contains '{m}'")
    return score, evidence


def score_adapter(adapter, obs):
    detect = adapter.get("detect", {}) or {}
    total = 0
    ev = []

    s, e = _header_match(obs["headers"], detect.get("headers_any"))
    total += s
    ev.extend(e)

    s, e = _cookie_match(obs["cookies"], detect.get("cookies_any"))
    total += s
    ev.extend(e)

    s, e = _html_match(obs["html"], detect.get("html_contains"))
    total += s
    ev.extend(e)

    s, e = _meta_match(obs["meta"], detect.get("meta_generator"))
    total += s
    ev.extend(e)

    s, e = _path_markers(obs["url"], detect.get("url_markers"))
    total += s
    ev.extend(e)

    return total, ev


def match(url):
    obs = _collect_observations(url)
    if obs is None:
        return {
            "adapter": adapter_loader.get("generic"),
            "score": 0,
            "evidence": ["target unreachable"],
            "observations": None,
        }

    candidates = []
    for adapter in adapter_loader.load_all():
        if adapter.get("id") == "generic":
            continue
        score, evidence = score_adapter(adapter, obs)
        candidates.append({"adapter": adapter, "score": score, "evidence": evidence})

    candidates.sort(key=lambda x: -x["score"])
    top = candidates[0] if candidates else None

    if not top or top["score"] < 30:
        generic = adapter_loader.get("generic") or {"id": "generic", "name": "Generic"}
        return {
            "adapter": generic,
            "score": top["score"] if top else 0,
            "evidence": top["evidence"] if top else [],
            "observations": obs,
            "alternatives": candidates[:3],
        }

    return {
        "adapter": top["adapter"],
        "score": top["score"],
        "evidence": top["evidence"],
        "observations": obs,
        "alternatives": candidates[:3],
    }
