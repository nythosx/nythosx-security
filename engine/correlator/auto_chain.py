from __future__ import annotations

from .models import AttackChain, ChainVerdict


RULES = [
    {
        "id": "auto-env-plus-ssrf-cloud",
        "name": "Local Env Leak + Cloud Metadata SSRF",
        "requires": ["env-file-exposure", "ssrf-cloud-metadata"],
        "severity": "critical",
        "narrative": ("Env file leaks APP_KEY and DB credentials locally. "
                      "SSRF reaches cloud metadata to pull IAM role "
                      "credentials. Combined: local secrets plus cloud "
                      "account access."),
    },
    {
        "id": "auto-open-redirect-plus-oauth-state",
        "name": "Open Redirect + OAuth Missing State",
        "requires": ["open-redirect", "oauth-missing-state"],
        "severity": "high",
        "narrative": ("Open redirect lets the attacker bounce victims "
                      "through a trusted domain. OAuth state is not "
                      "required, so CSRF against the callback is viable."),
    },
    {
        "id": "auto-crlf-plus-cache-poison",
        "name": "CRLF Injection + Cache Poisoning",
        "requires": ["crlf-injection", "cache-poisoning-probe"],
        "severity": "critical",
        "narrative": ("CRLF injection lets the attacker insert headers. "
                      "Combined with a cacheable response, the poisoned "
                      "response is served to every subsequent visitor."),
    },
    {
        "id": "auto-cors-plus-graphql-introspection",
        "name": "CORS Wildcard + GraphQL Introspection",
        "requires": ["cors-wildcard", "graphql-introspection"],
        "severity": "high",
        "narrative": ("Reflected CORS origin plus an open GraphQL schema "
                      "let any attacker page read the entire API surface "
                      "cross-origin."),
    },
    {
        "id": "auto-weak-pw-plus-enum-timing",
        "name": "Weak Password Policy + User Enumeration Timing",
        "requires": ["weak-password-policy", "user-enumeration-timing"],
        "severity": "critical",
        "narrative": ("Timing oracle confirms user enumeration. Weak "
                      "password policy accepts dictionary passwords. "
                      "Combined: targeted credential attacks on confirmed "
                      "accounts."),
    },
    {
        "id": "auto-nosql-plus-idor",
        "name": "NoSQL Injection + Authenticated IDOR",
        "requires": ["nosql-probe", "authed-idor"],
        "severity": "critical",
        "narrative": ("NoSQL operator injection bypasses query filters. "
                      "Combined with authed IDOR, the attacker walks "
                      "arbitrary user records."),
    },
    {
        "id": "auto-xxe-plus-host-header",
        "name": "XXE File Read + Host Header Injection",
        "requires": ["xxe-probe", "host-header-injection"],
        "severity": "critical",
        "narrative": ("XXE reaches internal file paths. Host header "
                      "injection lets the attacker reflect the leaked "
                      "content in a URL that any visitor can be tricked "
                      "into fetching."),
    },
    {
        "id": "auto-ssti-plus-openapi",
        "name": "SSTI + OpenAPI Spec Surface",
        "requires": ["ssti-probe", "openapi-fuzz"],
        "severity": "critical",
        "narrative": ("OpenAPI spec enumerates every endpoint and "
                      "parameter. SSTI on one of those parameters yields "
                      "code execution."),
    },
]


_PRIORITY = {
    ChainVerdict.CONFIRMED.value: 3,
    ChainVerdict.LIKELY.value: 2,
    ChainVerdict.THEORETICAL.value: 1,
    ChainVerdict.INCOMPLETE.value: 0,
}


def _extract_findings(findings):
    out = {}
    for f in findings or []:
        pid = None
        verdict = None
        confidence = None
        if isinstance(f, dict):
            pid = f.get("pattern_id") or f.get("capability") or f.get("id")
            verdict = f.get("verdict")
            confidence = f.get("confidence")
        else:
            pid = (getattr(f, "pattern_id", None)
                   or getattr(f, "capability", None))
            verdict = getattr(f, "verdict", None)
            confidence = getattr(f, "confidence", None)
        if hasattr(verdict, "value"):
            verdict = verdict.value
        if not pid:
            continue
        existing = out.get(pid)
        rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
        if existing is None or rank.get(verdict, 0) > rank.get(
                existing.get("verdict"), 0):
            out[pid] = {"verdict": verdict, "confidence": confidence}
    return out


def _compute_confidence(matched):
    confs = []
    for m in matched:
        c = m.get("confidence")
        if c is None:
            c = {"VULNERABLE": 0.9, "SUSPICIOUS": 0.6,
                 "PASS": 0.8, "UNKNOWN": 0.3}.get(m.get("verdict"), 0.3)
        try:
            confs.append(float(c))
        except (TypeError, ValueError):
            confs.append(0.3)
    if not confs:
        return 0.0
    prod = 1.0
    for c in confs:
        prod *= max(0.0001, c)
    return prod ** (1.0 / len(confs))


def generate(findings, threshold=0.7):
    flat = _extract_findings(findings)
    if not flat:
        return []

    out = []
    for rule in RULES:
        required = rule.get("requires") or []
        if not required:
            continue
        if not all(r in flat for r in required):
            continue

        matched = []
        for r in required:
            info = flat[r]
            matched.append({
                "pattern_id": r,
                "verdict": info.get("verdict"),
                "confidence": info.get("confidence"),
            })

        verdicts = [m["verdict"] for m in matched]
        if not all(v in ("VULNERABLE", "SUSPICIOUS") for v in verdicts):
            continue

        conf = _compute_confidence(matched)
        if all(v == "VULNERABLE" for v in verdicts):
            v = (ChainVerdict.CONFIRMED.value if conf >= threshold
                 else ChainVerdict.LIKELY.value)
        elif any(v == "VULNERABLE" for v in verdicts):
            v = ChainVerdict.LIKELY.value
        else:
            v = ChainVerdict.THEORETICAL.value

        chain = AttackChain(
            id=rule["id"],
            name=rule["name"],
            prerequisites=list(required),
            narrative=rule.get("narrative", ""),
            severity=rule.get("severity", "high"),
            verdict=v,
            confidence=round(conf, 4),
            matched=matched,
            missing=[],
            steps=[],
        )
        out.append(chain)

    return out


__all__ = ["generate", "RULES"]
