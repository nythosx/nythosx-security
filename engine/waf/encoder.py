from __future__ import annotations

import re
import urllib.parse


def _case_alternate(s):
    out = []
    flip = False
    for c in s:
        if c.isalpha():
            out.append(c.upper() if flip else c.lower())
            flip = not flip
        else:
            out.append(c)
    return "".join(out)


def _unicode_escape(s):
    out = []
    for c in s:
        if c.isalpha():
            out.append("\\u" + format(ord(c), "04x"))
        else:
            out.append(c)
    return "".join(out)


def _js_escape(s):
    out = []
    for c in s:
        if c.isalpha():
            out.append("\\x" + format(ord(c), "02x"))
        else:
            out.append(c)
    return "".join(out)


def _html_entity(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;")
             .replace("'", "&#39;"))


def _url_single(s):
    return urllib.parse.quote(s, safe="")


def _url_double(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _url_unicode(s):
    out = []
    for c in s:
        out.append("%u" + format(ord(c), "04x"))
    return "".join(out)


def _whitespace_insert(s):
    return s.replace(" ", "/**/") if " " in s else s


def _tab_insert(s):
    return s.replace(" ", "\t")


def _comment_insert(s):
    keywords = [" or ", " and ", " union ", " select ", " where ",
                " from ", " order by "]
    out = s
    for kw in keywords:
        if kw in out.lower():
            out = out.replace(kw, "/**/" + kw.strip() + "/**/")
    return out


def _null_byte(s):
    return s.replace(" ", "%00")


def _mix_case_keywords(s):
    keywords = ["or", "and", "union", "select", "where", "from", "insert",
                "update", "delete", "sleep", "waitfor", "delay"]
    out = s
    for kw in keywords:
        lower = out.lower()
        idx = lower.find(kw)
        while idx >= 0:
            mixed = kw.upper() if idx % 2 == 0 else kw.capitalize()
            out = out[:idx] + mixed + out[idx + len(kw):]
            lower = out.lower()
            idx = lower.find(kw, idx + len(kw))
    return out


_TAG_OPEN_RE = re.compile(
    r"<(script|img|svg|iframe|style|body|input|details|video|audio|"
    r"marquee|object|embed|noscript|math|form|a)\b",
    re.IGNORECASE,
)


def _tag_split(s):
    def _sub(m):
        tag = m.group(1)
        if len(tag) < 2:
            return m.group(0)
        mid = len(tag) // 2
        return "<" + tag[:mid] + "<" + tag[mid:] + ">" + tag[mid:]
    return _TAG_OPEN_RE.sub(_sub, s)


def _js_unicode_escape_in_script(s):
    return (s.replace("<", "\\u003c").replace(">", "\\u003e")
             .replace("/", "\\u002f").replace('"', "\\u0022")
             .replace("'", "\\u0027"))


def _ensure_script_closer(s):
    if "<script" in s.lower() and "</script" not in s.lower():
        return s + "</script>"
    return s


def _comment_breakout(s):
    if "<!--" not in s:
        return s
    return s.replace("<!--", "<!--break-->", 1)


def _sgml_short_comment(s):
    if "<![CDATA[" in s:
        return s.replace("<![CDATA[", "<!x[", 1)
    return s


def _proto_null_byte(s):
    if "javascript:" in s.lower():
        return re.sub(r"javascript:", "java\x00script:", s,
                      flags=re.IGNORECASE)
    return s


def _round2_special(s):
    return re.sub(r"([/=()])",
                  lambda m: "%%%02x" % ord(m.group(1)), s)


def _round3_special(s):
    return re.sub(r"([/=()])",
                  lambda m: "%%25%02x" % ord(m.group(1)), s)


def _waf_specific(s, waf):
    out = []
    w = (waf or "").lower()
    if "cloudflare" in w:
        out.append(("cf_case", _case_alternate(s)))
        out.append(("cf_unicode", _unicode_escape(s)))
    elif "akamai" in w:
        out.append(("ak_ws", _whitespace_insert(s)))
        out.append(("ak_case", _mix_case_keywords(s)))
    elif "aws" in w or "cloudfront" in w:
        out.append(("aws_url_double", _url_double(s)))
        out.append(("aws_unicode", _url_unicode(s)))
    elif "imperva" in w or "incapsula" in w:
        out.append(("imp_comment", _comment_insert(s)))
        out.append(("imp_case", _case_alternate(s)))
    elif "f5" in w or "bigip" in w:
        out.append(("f5_tab", _tab_insert(s)))
        out.append(("f5_case", _mix_case_keywords(s)))
    elif "sucuri" in w:
        out.append(("suc_nested", _url_double(s)))
        out.append(("suc_html", _html_entity(s)))
    elif "fastly" in w or "varnish" in w:
        out.append(("fastly_ws", _whitespace_insert(s)))
    elif "modsecurity" in w or "mod_security" in w:
        out.append(("mod_nested", _url_double(s)))
        out.append(("mod_case", _case_alternate(s)))
    return out


def encode(payload, waf=None, max_mutations=30):
    if not payload:
        return []
    mutations = [
        ("url_single", _url_single(payload)),
        ("url_double", _url_double(payload)),
        ("html_entity", _html_entity(payload)),
        ("unicode_escape", _unicode_escape(payload)),
        ("js_escape", _js_escape(payload)),
        ("case_alternate", _case_alternate(payload)),
        ("whitespace_comment", _whitespace_insert(payload)),
        ("tab_insert", _tab_insert(payload)),
        ("comment_insert", _comment_insert(payload)),
        ("null_byte", _null_byte(payload)),
        ("mix_case_keywords", _mix_case_keywords(payload)),
        ("url_unicode", _url_unicode(payload)),
        ("tag_split", _tag_split(payload)),
        ("js_unicode_escape", _js_unicode_escape_in_script(payload)),
        ("ensure_script_closer", _ensure_script_closer(payload)),
        ("comment_breakout", _comment_breakout(payload)),
        ("sgml_short_comment", _sgml_short_comment(payload)),
        ("proto_null_byte", _proto_null_byte(payload)),
        ("round2_special", _round2_special(payload)),
        ("round3_special", _round3_special(payload)),
    ]
    mutations = [(k, v) for k, v in mutations if v and v != payload]
    if waf:
        mutations.extend(_waf_specific(payload, waf))
    seen = set()
    out = []
    for name, val in mutations:
        key = (name, val)
        if key in seen:
            continue
        seen.add(key)
        out.append((name, val))
        if len(out) >= max_mutations:
            break
    return out


def encode_all(payload, wafs=None, max_per_waf=10):
    if not wafs:
        return encode(payload, max_mutations=max_per_waf)
    out = []
    for w in wafs:
        for name, val in encode(payload, waf=w, max_mutations=max_per_waf):
            out.append((w + ":" + name, val))
    return out


def adaptive_encode(payload, waf=None, max_rounds=3, max_mutations=30,
                    feedback_fn=None, preferred_order=None):
    if not isinstance(payload, str) or not payload:
        return None, payload if isinstance(payload, str) else ""
    seen = set()
    current = payload
    for _round in range(max(1, int(max_rounds))):
        candidates = encode(current, waf=waf, max_mutations=max_mutations)
        if preferred_order:
            order_map = {n: i for i, n in enumerate(preferred_order)}
            candidates.sort(key=lambda kv: order_map.get(kv[0], 999))
        attempted = False
        for name, mutated in candidates:
            if not isinstance(mutated, str) or not mutated:
                continue
            if mutated in seen or mutated == payload:
                continue
            seen.add(mutated)
            if feedback_fn is None:
                return name, mutated
            try:
                status, _body = feedback_fn(mutated)
            except Exception:
                status = 0
            attempted = True
            if status and status not in (403, 406, 419, 429, 503):
                return name, mutated
        if not attempted:
            break
        if candidates:
            current = candidates[-1][1]
    return None, payload


__all__ = ["encode", "encode_all", "adaptive_encode"]
