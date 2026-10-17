"""Charset & Unicode normalization differential.

Sends the same payload in encodings the backend may interpret differently.
Detects:
  - explicit charset param honored vs ignored
  - UTF-16 with UTF-8 declared (rare but some stacks honor BOM)
  - overlong UTF-8 (`%C0%AE` for `.`)
  - Unicode normalization form collapse (NFKC maps Cyrillic `а` to Latin `a`)
  - U+2028 / U+2029 in JSON strings (JS line terminator breakout)
"""
from __future__ import annotations

import json
import unicodedata

from ..config import load_engine
from ..roe_guard import ROEGuard, ROEViolation
from .. import http as _http


HOMOGLYPHS = {
    "a": ("\u0430", "\uff41"),
    "e": ("\u0435", "\uff45"),
    "o": ("\u043e", "\uff4f"),
    "i": ("\u0456", "\uff49"),
    "u": ("\u0443", "\uff55"),
    "c": ("\u0441", "\uff43"),
    "s": ("\u0455", "\uff53"),
    "m": ("\u043c", "\u217f"),
}


PATH_TRAVERSALS = [
    "..%2f", "..%2F", "..%255c", "..%5c", "..%c0%af", "..%c1%9c",
    "....//", "..\\/", "..%252f", "..%2e%2e%2f",
]

UNICODE_LINE_SEPARATORS = ("\u2028", "\u2029")


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="POST"):
    if guard is None:
        try:
            guard = ROEGuard(engine_cfg=load_engine())
        except Exception as e:
            return "ROE guard unavailable (fail-closed): %s" % e
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def make_homoglyphs(payload):
    out = []
    for ch, repls in HOMOGLYPHS.items():
        for r in repls:
            if ch in payload:
                out.append((ch, r, payload.replace(ch, r, 1)))
                break
    return out


def normalize(text, form):
    try:
        return unicodedata.normalize(form, text)
    except Exception:
        return text


def make_charset_variants(payload):
    """Return [(label, content_type, body_bytes)]."""
    out = []
    canonical_json = json.dumps({"value": payload},
                                 ensure_ascii=False)
    out.append(("utf8_plain", "application/json; charset=utf-8",
                canonical_json.encode("utf-8")))
    out.append(("utf16le_declared_utf8", "application/json; charset=utf-8",
                canonical_json.encode("utf-16-le")))
    out.append(("utf16le_declared_utf16", "application/json; charset=utf-16le",
                canonical_json.encode("utf-16-le")))
    _utf7_body = (payload.encode("ascii") if payload.isascii()
                   else b"value=probe")
    out.append(("utf7_declared", "application/json; charset=utf-7",
                _utf7_body))
    out.append(("overlong_utf8_dot",
                "application/x-www-form-urlencoded",
                b"value=%C0%AE%C0%AE"))
    for label, form in (("nfc", "NFC"), ("nfd", "NFD"),
                         ("nfkc", "NFKC"), ("nfkd", "NFKD")):
        out.append(("normalized_%s" % label, "application/json",
                    json.dumps({"value": normalize(payload, form)},
                               ensure_ascii=False)
                    .encode("utf-8")))
    return out


def probe_charsets(url, param="value", payload="café", timeout=8,
                    roe_guard=None, verify=None):
    if verify is None:
        verify = _verify_tls()
    attempts = []
    baseline_status = None
    baseline_len = 0
    viol = _roe_block(roe_guard, url, "POST")
    if viol:
        return {"blocked": True, "error": "ROE_BLOCK: " + viol}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r0 = c.post(url, json={param: "probe_baseline"},
                        headers={"Content-Type": "application/json"})
        baseline_status = r0.status_code
        baseline_len = len(r0.text or "")
    except Exception:
        pass
    for label, ct, body in make_charset_variants(payload):
        viol = _roe_block(roe_guard, url, "POST")
        if viol:
            return {"blocked": True, "error": "ROE_BLOCK: " + viol}
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.post(url, content=body,
                           headers={"Content-Type": ct})
            attempts.append({
                "label": label,
                "content_type": ct,
                "status": r.status_code,
                "body_len": len(r.text or ""),
                "baseline_status": baseline_status,
                "baseline_len": baseline_len,
                "diverges_from_baseline": (
                    r.status_code != baseline_status
                    or abs(len(r.text or "") - baseline_len)
                    > max(50, int(baseline_len * 0.15))
                ),
            })
        except Exception as e:
            attempts.append({
                "label": label,
                "content_type": ct,
                "error": "%s: %s" % (type(e).__name__, e),
            })
    return {"attempts": attempts, "baseline_status": baseline_status}


def analyze_charset_divergence(attempts):
    divergent = [a["label"] for a in attempts
                 if a.get("diverges_from_baseline")]
    statuses = {}
    for a in attempts:
        st = a.get("status")
        if st is None:
            continue
        statuses.setdefault(st, []).append(a["label"])
    return {
        "divergent_labels": divergent,
        "status_distribution": statuses,
        "charset_sensitive": len(set(statuses.keys())) > 1,
    }


def unicode_line_separator_variants(payload):
    out = []
    for sep in UNICODE_LINE_SEPARATORS:
        out.append({
            "label": "u%04x_embedded" % ord(sep),
            "body": json.dumps({"value": "x" + sep + payload},
                               ensure_ascii=False),
            "content_type": "application/json",
        })
    return out


def homoglyph_bypass_probe(url, param="username", baseline_value="admin",
                            timeout=8, roe_guard=None, verify=None):
    if verify is None:
        verify = _verify_tls()
    variants = make_homoglyphs(baseline_value)
    attempts = []
    for orig, repl, mutated in variants:
        viol = _roe_block(roe_guard, url, "POST")
        if viol:
            return {"blocked": True, "error": "ROE_BLOCK: " + viol}
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.post(url, json={param: mutated},
                           headers={"Content-Type": "application/json"})
            attempts.append({
                "original": orig,
                "replacement": repl,
                "hex_replacement": "\\u%04x" % ord(repl),
                "status": r.status_code,
                "accepted": 200 <= r.status_code < 300,
            })
        except Exception as e:
            attempts.append({"original": orig, "replacement": repl,
                              "error": "%s: %s" % (type(e).__name__, e)})
    return {"attempts": attempts}


def detect_charset_divergence(url, param="value", payload="café",
                                timeout=8, roe_guard=None):
    result = probe_charsets(url, param=param, payload=payload,
                             timeout=timeout, roe_guard=roe_guard)
    if result.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": result["error"],
                "evidence": {}}
    attempts = result["attempts"]
    live = [a for a in attempts if not a.get("error")]
    if not live:
        return {"verdict": "UNKNOWN",
                "reason": "no charset probes completed",
                "evidence": {"attempts": attempts}}
    divergence = analyze_charset_divergence(attempts)
    if divergence["charset_sensitive"]:
        return {
            "verdict": "VULNERABLE",
            "reason": ("charset normalization diverges: %s" %
                       divergence["status_distribution"]),
            "evidence": {"attempts": attempts,
                         "divergence": divergence},
            "divergence": divergence,
        }
    return {
        "verdict": "PASS",
        "reason": "charset / normalization variants behave identically",
        "evidence": {"attempts": attempts,
                     "divergence": divergence},
        "divergence": divergence,
    }
