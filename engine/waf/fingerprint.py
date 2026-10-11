from __future__ import annotations


SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id",
                    "cf-connecting-ip"],
        "server_contains": "cloudflare",
        "body_contains": ["attention required", "cloudflare ray id",
                          "error 1020", "error 1015"],
    },
    "akamai": {
        "headers": ["x-akamai-", "akamai-grn", "akamai-origin-hop"],
        "server_contains": "akamai",
        "body_contains": ["reference #", "akamai ghost"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id"],
        "server_contains": "cloudfront",
        "body_contains": ["request blocked", "aws waf"],
    },
    "imperva_incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server_contains": "incapsula",
        "body_contains": ["incapsula incident id", "incap_ses",
                          "_incap_"],
    },
    "f5_bigip": {
        "headers": ["x-wa-info", "x-cnection"],
        "server_contains": "big-ip",
        "body_contains": ["the requested url was rejected",
                          "please consult with your administrator",
                          "support id"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server_contains": "sucuri",
        "body_contains": ["sucuri website firewall", "cloudproxy",
                          "access denied - sucuri"],
    },
    "fastly": {
        "headers": ["x-served-by", "x-fastly-request-id",
                    "x-timer", "fastly-io-info"],
        "server_contains": "varnish",
        "body_contains": ["fastly error"],
    },
    "modsecurity": {
        "headers": ["x-mod-security"],
        "server_contains": "",
        "body_contains": ["mod_security", "modsecurity", "not acceptable"],
    },
    "barracuda": {
        "headers": ["x-barracuda"],
        "server_contains": "barracuda",
        "body_contains": ["barracuda web application firewall"],
    },
}


def identify(response):
    if response is None:
        return {"waf": None, "confidence": 0.0, "evidence": [],
                "all_hits": []}
    headers = {k.lower(): v for k, v in (response.get("headers") or {}).items()}
    body = ((response.get("body") or "")[:8000]).lower()
    server = (headers.get("server") or "").lower()

    hits = []
    for waf, sig in SIGNATURES.items():
        evidence = []
        for h in sig.get("headers", []):
            for actual in headers.keys():
                if h in actual:
                    evidence.append("header:" + actual)
                    break
        sc = sig.get("server_contains") or ""
        if sc and sc in server:
            evidence.append("server:" + server[:40])
        for b in sig.get("body_contains", []):
            if b in body:
                evidence.append("body:" + b[:40])
                break
        if evidence:
            hits.append((waf, evidence))

    if not hits:
        return {"waf": None, "confidence": 0.0, "evidence": [],
                "all_hits": []}

    waf, evidence = hits[0]
    confidence = min(1.0, 0.3 + 0.2 * len(evidence))
    return {
        "waf": waf,
        "confidence": round(confidence, 3),
        "evidence": evidence,
        "all_hits": [h[0] for h in hits],
    }


def is_waf_block(status, response=None):
    if status not in (403, 406, 419, 429, 503):
        return False
    if response is None:
        return status in (403, 406, 419)
    fp = identify(response)
    return fp.get("waf") is not None


__all__ = ["identify", "is_waf_block", "SIGNATURES"]
