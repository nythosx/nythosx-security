import json
import re
import secrets
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from .browser import _import_playwright, BrowserUnavailable
from . import http as _http


SOURCES = {
    "hash": "location.hash",
    "search": "location.search",
    "referrer": "document.referrer",
    "window_name": "window.name",
}


SINK_HOOK_SCRIPT = r"""
(function(){
  if (window.__sec_checker_hook_installed) return;
  window.__sec_checker_hook_installed = true;
  window.__sec_checker_sink_hits = [];
  window.__sec_checker_xss_hit = null;

  function rec(sink, value) {
    try {
      var v = String(value);
      window.__sec_checker_sink_hits.push({
        sink: sink,
        value: v.slice(0, 2000),
        stack: (new Error()).stack ? String((new Error()).stack).slice(0, 800) : ""
      });
    } catch (e) {}
  }

  try {
    var ih = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
    if (ih && ih.set) {
      Object.defineProperty(Element.prototype, "innerHTML", {
        configurable: true, enumerable: ih.enumerable,
        get: ih.get,
        set: function(v) { rec("innerHTML", v); return ih.set.call(this, v); }
      });
    }
  } catch (e) {}

  try {
    var oh = Object.getOwnPropertyDescriptor(Element.prototype, "outerHTML");
    if (oh && oh.set) {
      Object.defineProperty(Element.prototype, "outerHTML", {
        configurable: true, enumerable: oh.enumerable,
        get: oh.get,
        set: function(v) { rec("outerHTML", v); return oh.set.call(this, v); }
      });
    }
  } catch (e) {}

  try {
    var ow = document.write;
    document.write = function() {
      var s = Array.prototype.slice.call(arguments).join("");
      rec("document.write", s);
      return ow.apply(document, arguments);
    };
  } catch (e) {}

  try {
    var owl = document.writeln;
    document.writeln = function() {
      var s = Array.prototype.slice.call(arguments).join("");
      rec("document.writeln", s);
      return owl.apply(document, arguments);
    };
  } catch (e) {}

  try {
    var oe = window.eval;
    window.eval = function(s) { rec("eval", s); return oe.call(window, s); };
  } catch (e) {}

  try {
    var OF = window.Function;
    var NF = function() {
      rec("Function", Array.prototype.slice.call(arguments).join(","));
      return OF.apply(this, arguments);
    };
    NF.prototype = OF.prototype;
    window.Function = NF;
  } catch (e) {}

  try {
    var ost = window.setTimeout;
    window.setTimeout = function(fn, ms) {
      if (typeof fn === "string") rec("setTimeout", fn);
      return ost.apply(window, arguments);
    };
  } catch (e) {}

  try {
    var osi = window.setInterval;
    window.setInterval = function(fn, ms) {
      if (typeof fn === "string") rec("setInterval", fn);
      return osi.apply(window, arguments);
    };
  } catch (e) {}

  try {
    var osa = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
      try { if (/^on/i.test(String(name))) rec("setAttribute:" + name, value); } catch (e) {}
      return osa.call(this, name, value);
    };
  } catch (e) {}

  try {
    var oiah = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(pos, html) {
      rec("insertAdjacentHTML", html);
      return oiah.call(this, pos, html);
    };
  } catch (e) {}

  try {
    var ops = history.pushState;
    history.pushState = function() {
      rec("history.pushState", String(arguments[2] || ""));
      return ops.apply(history, arguments);
    };
  } catch (e) {}

  try {
    var ors = history.replaceState;
    history.replaceState = function() {
      rec("history.replaceState", String(arguments[2] || ""));
      return ors.apply(history, arguments);
    };
  } catch (e) {}

  try {
    var sd = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, "srcdoc");
    if (sd && sd.set) {
      Object.defineProperty(HTMLIFrameElement.prototype, "srcdoc", {
        configurable: true, enumerable: sd.enumerable,
        get: sd.get,
        set: function(v) { rec("iframe.srcdoc", v); return sd.set.call(this, v); }
      });
    }
  } catch (e) {}

  try {
    var ot = trustedTypes;
    if (ot && typeof ot.createPolicy === "function") {
      var _origCreate = ot.createPolicy.bind(ot);
      ot.createPolicy = function(name, opts) {
        try {
          window.__sec_checker_sink_hits.push({
            sink: "trustedTypes.createPolicy",
            value: "policy=" + name + " keys=" + Object.keys(opts || {}).join(","),
            stack: ""
          });
          var wrapped = {};
          Object.keys(opts || {}).forEach(function(k){
            var fn = opts[k];
            if (typeof fn === "function") {
              wrapped[k] = function() {
                var r = fn.apply(this, arguments);
                try {
                  window.__sec_checker_sink_hits.push({
                    sink: "trustedTypes.policy." + name + "." + k,
                    value: String(r).slice(0, 800),
                    stack: ""
                  });
                } catch (e) {}
                return r;
              };
            } else {
              wrapped[k] = fn;
            }
          });
          return _origCreate(name, wrapped);
        } catch (e) {
          return _origCreate(name, opts);
        }
      };
    }
  } catch (e) {}

  try {
    window.addEventListener("message", function(ev){
      try {
        rec("postMessage.data", typeof ev.data === "string" ? ev.data : JSON.stringify(ev.data));
      } catch (e) {}
    });
  } catch (e) {}

  try {
    var _origError = window.onerror;
    window.onerror = function(msg, src, line, col, err) {
      try {
        var s = String(msg);
        var m = s.match(/SC_HTML_[0-9a-f]{16}/i);
        if (m) window.__sec_checker_xss_hit = m[0];
      } catch (e) {}
      if (typeof _origError === "function") return _origError.apply(this, arguments);
      return false;
    };
  } catch (e) {}
})();
"""


MXSS_PAYLOADS = [
    '<form id="outer"><div></form><form id="inner"><input>',
    '<noscript><style></noscript>SC_PAYLOAD_HERE',
    '<xmp>SC_PAYLOAD_HERE</xmp>',
    '<noembed>SC_PAYLOAD_HERE</noembed>',
    '<noframes>SC_PAYLOAD_HERE</noframes>',
    '<iframe>SC_PAYLOAD_HERE</iframe>',
    '<math><mtext><table><mglyph><style><!--</style>SC_PAYLOAD_HERE',
    '<svg></p><style><a id="</style><img src=x onerror=SC_PAYLOAD_HERE>"',
    '<form><math><mtext></form><form><mglyph><svg><mtext><form><mi></form>'
    '<form><mglyph><desc><xmp>SC_PAYLOAD_HERE',
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


def _new_probe():
    return "SC_PROBE_" + secrets.token_hex(8)


def _new_html_probe():
    return "SC_HTML_" + secrets.token_hex(8)


def _html_payload(marker):
    return (
        '<img src=x onerror="window.__sec_checker_xss_hit=\'' + marker + '\'">'
    )


def _inject_into_hash(url, value):
    p = urlparse(url)
    return urlunparse(p._replace(fragment=value))


def _inject_into_query(url, key, value):
    p = urlparse(url)
    q = parse_qs(p.query)
    q[key] = [value]
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def _probe_one_source(url, source, marker, html_marker, timeout_ms, verify_tls):
    sync_playwright = _import_playwright()
    result = {"source": source, "sink_hits": [], "xss_hit": None,
              "error": None, "final_url": None}
    payload_marker = _html_payload(html_marker) if source != "referrer" else marker
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(ignore_https_errors=not verify_tls)
                page = context.new_page()
                page.add_init_script(SINK_HOOK_SCRIPT)
                page_errors = []
                page.on("pageerror", lambda e: page_errors.append(str(e)[:400]))

                if source == "hash":
                    target = _inject_into_hash(url, marker + "&" + payload_marker)
                    page.goto(target, timeout=timeout_ms, wait_until="load")
                elif source == "search":
                    target = _inject_into_query(url, "sc_probe", marker + " " + payload_marker)
                    page.goto(target, timeout=timeout_ms, wait_until="load")
                elif source == "window_name":
                    page.goto(url, timeout=timeout_ms, wait_until="load")
                    page.evaluate("(v) => { window.name = v; }", marker + " " + payload_marker)
                    page.reload(timeout=timeout_ms, wait_until="load")
                elif source == "referrer":
                    page.goto("about:blank")
                    page.set_extra_http_headers({"Referer": url + "#" + marker + "&" + payload_marker})
                    page.goto(url, timeout=timeout_ms, wait_until="load")
                else:
                    return result

                try:
                    page.wait_for_timeout(800)
                except Exception:
                    pass

                hits = page.evaluate("() => window.__sec_checker_sink_hits || []")
                xss_hit = page.evaluate("() => window.__sec_checker_xss_hit")
                result["sink_hits"] = hits
                result["xss_hit"] = xss_hit
                result["final_url"] = page.url
                result["page_errors"] = page_errors
            finally:
                browser.close()
    except BrowserUnavailable:
        raise
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result


BENIGN_SINKS = {"history.pushState", "history.replaceState"}


def _filter_hits(hits, marker, html_marker):
    plain, html = [], []
    for h in hits or []:
        if h.get("sink") in BENIGN_SINKS:
            continue
        v = h.get("value") or ""
        if html_marker and html_marker in v:
            html.append(h)
        elif marker and marker in v:
            plain.append(h)
    return plain, html


def _evaluate_sink_flow(results, marker, html_marker):
    findings = []
    for r in results:
        if r.get("error"):
            continue
        plain, html = _filter_hits(r.get("sink_hits"), marker, html_marker)
        xss_hit = r.get("xss_hit")
        if xss_hit == html_marker:
            code_sinks = [h for h in html if h["sink"] in (
                "eval", "Function", "setTimeout", "setInterval",
                "document.write", "document.writeln", "insertAdjacentHTML",
                "iframe.srcdoc",
            ) or h["sink"].startswith("setAttribute:on")
                or h["sink"].startswith("trustedTypes.policy")]
            html_sinks = [h for h in html if h["sink"] in (
                "innerHTML", "outerHTML")]
            findings.append({
                "source": r["source"],
                "kind": "executable",
                "sinks": [h["sink"] for h in (code_sinks or html_sinks or html)],
                "evidence": {"xss_hit_marker": html_marker,
                             "final_url": r.get("final_url")},
            })
        elif html:
            findings.append({
                "source": r["source"],
                "kind": "html_reachable",
                "sinks": [h["sink"] for h in html],
                "evidence": {"final_url": r.get("final_url")},
            })
        elif plain:
            findings.append({
                "source": r["source"],
                "kind": "reflected_to_sink",
                "sinks": [h["sink"] for h in plain],
                "evidence": {"final_url": r.get("final_url")},
            })
    return findings


def _check_trusted_types(page):
    result = {"enforced": False, "policies_seen": [], "unsafe_policies": []}
    try:
        resp = page.goto(page.url or "about:blank")
    except Exception:
        return result
    return result


def _trusted_types_from_response(headers):
    csp = ""
    for k, v in (headers or {}).items():
        if k.lower() == "content-security-policy":
            csp = v
            break
    enforced = "require-trusted-types-for" in csp and "'script'" in csp
    return {"enforced": enforced, "csp_header": csp[:800]}


def _mxss_probe(url, timeout_ms, verify_tls):
    sync_playwright = _import_playwright()
    findings = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                for tmpl in MXSS_PAYLOADS:
                    html_marker = _new_html_probe()
                    inner_payload = _html_payload(html_marker)
                    payload = tmpl.replace("SC_PAYLOAD_HERE", inner_payload)

                    for source in ("hash", "search"):
                        context = browser.new_context(ignore_https_errors=not verify_tls)
                        try:
                            page = context.new_page()
                            page.add_init_script(SINK_HOOK_SCRIPT)
                            if source == "hash":
                                target = _inject_into_hash(url, payload)
                            else:
                                target = _inject_into_query(url, "sc_mxss", payload)
                            try:
                                page.goto(target, timeout=timeout_ms, wait_until="load")
                            except Exception:
                                continue
                            try:
                                page.wait_for_timeout(600)
                            except Exception:
                                pass
                            xss_hit = page.evaluate("() => window.__sec_checker_xss_hit")
                            if xss_hit == html_marker:
                                findings.append({
                                    "vector": "mxss",
                                    "source": source,
                                    "payload": payload[:200],
                                    "marker": html_marker,
                                    "final_url": page.url,
                                })
                        finally:
                            context.close()
            finally:
                browser.close()
    except BrowserUnavailable:
        raise
    except Exception:
        pass
    return findings


def _collect_csp_headers(url, headers, timeout, verify_tls, roe_guard):
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return {"error": f"ROE_BLOCK: {viol}"}
    try:
        import httpx
        with _http.Client(timeout=timeout, verify=verify_tls,
                          follow_redirects=True) as c:
            r = c.get(url, headers=headers or {})
        return dict(r.headers)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def _scan_impl(url, headers=None, timeout_ms=15000, roe_guard=None, verify_tls=None,
         include_mxss=True):
    if verify_tls is None:
        verify_tls = _verify_tls()

    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return {"url": url, "verdict": "UNKNOWN",
                "reason": f"ROE_BLOCK: {viol}", "results": {}}

    out = {
        "url": url,
        "verdict": "UNKNOWN",
        "reason": "",
        "results": {
            "sources": [],
            "flow_findings": [],
            "trusted_types": None,
            "mxss": [],
            "csp": None,
        },
    }

    try:
        _import_playwright()
    except BrowserUnavailable as e:
        out["reason"] = f"playwright not available: {e}"
        return out

    probe = _new_probe()
    html_probe = _new_html_probe()

    source_results = []
    for source in SOURCES:
        r = _probe_one_source(url, source, probe, html_probe, timeout_ms, verify_tls)
        source_results.append(r)

    out["results"]["sources"] = [
        {"source": r["source"], "sink_hits": len(r.get("sink_hits") or []),
         "xss_hit": r.get("xss_hit"), "error": r.get("error")}
        for r in source_results
    ]

    findings = _evaluate_sink_flow(source_results, probe, html_probe)
    out["results"]["flow_findings"] = findings

    csp_headers = _collect_csp_headers(url, headers, timeout_ms / 1000,
                                       verify_tls, roe_guard)
    if isinstance(csp_headers, dict) and "error" not in csp_headers:
        out["results"]["csp"] = _trusted_types_from_response(csp_headers)

    if include_mxss:
        mxss = _mxss_probe(url, timeout_ms, verify_tls)
        out["results"]["mxss"] = mxss

    executable = [f for f in findings if f.get("kind") == "executable"]
    html_reach = [f for f in findings if f.get("kind") == "html_reachable"]
    reflected = [f for f in findings if f.get("kind") == "reflected_to_sink"]

    if executable:
        out["verdict"] = "VULNERABLE"
        out["reason"] = (f"DOM XSS confirmed via source→sink flow "
                         f"({executable[0]['source']} → "
                         f"{', '.join(executable[0]['sinks'])})")
    elif out["results"]["mxss"]:
        out["verdict"] = "VULNERABLE"
        out["reason"] = (f"mXSS confirmed via "
                         f"{out['results']['mxss'][0]['vector']} on "
                         f"{out['results']['mxss'][0]['source']}")
    elif html_reach:
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = (f"unencoded HTML reaches a sink "
                         f"({html_reach[0]['source']} → "
                         f"{', '.join(html_reach[0]['sinks'])}) — manual "
                         f"verification recommended")
    elif reflected:
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = (f"user-controlled value reaches a sink "
                         f"({reflected[0]['source']} → "
                         f"{', '.join(reflected[0]['sinks'])}) but no script "
                         f"execution observed")
    else:
        any_ok = any(not r.get("error") for r in source_results)
        if not any_ok:
            out["reason"] = "all source probes failed to load"
        else:
            out["verdict"] = "PASS"
            out["reason"] = "no source→sink flow detected"

    return out

def scan(*args, **kwargs):
    from .contract import make_result
    raw = _scan_impl(*args, **kwargs)
    return make_result(raw, capability="dom_xss", args=args, kwargs=kwargs)
