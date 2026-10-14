from __future__ import annotations

from dataclasses import dataclass, field

from . import loader


OWASP_CATEGORIES = [
    "A01", "A02", "A03", "A04", "A05",
    "A06", "A07", "A08", "A09", "A10",
]


OWASP_TO_CAPABILITIES = {
    "A01": ["auth-bypass-probe", "authed-idor", "idor-sequential",
            "mass-assignment", "cors-wildcard", "api-cors-preflight",
            "ssrf-cloud-metadata"],
    "A02": ["security-headers-missing", "authed-security-headers",
            "server-disclosure", "api-exposed-headers", "env-file-exposure",
            "js-bundle-secrets", "laravel-debug-mode", "graphql-introspection",
            "cache-poisoning-probe", "http-methods-allowed"],
    "A03": ["sca-scan"],
    "A04": ["jwt-weak-secret", "jwt-advanced-analysis"],
    "A05": ["dom-xss-advanced", "graphql-deep-security",
            "llm-prompt-injection", "llm-output-handling"],
    "A06": ["bizlogic-scan", "idempotency-violation", "race-condition-basic",
            "race-condition-authed", "race-advanced"],
    "A07": ["jwt-analysis", "rate-limit-absent", "user-enumeration-timing",
            "cookie-flags-missing", "timing-vs-baseline"],
    "A08": ["openapi-fuzz"],
    "A09": [],
    "A10": ["api-error-handling", "api-info-disclosure"],
}


ATTACK_SURFACES = {
    "rest": ["openapi-fuzz", "security-headers-missing", "cors-wildcard",
             "api-cors-preflight", "authed-idor", "idor-sequential",
             "mass-assignment", "api-error-handling", "api-info-disclosure"],
    "graphql": ["graphql-deep-security", "graphql-introspection"],
    "llm": ["llm-prompt-injection", "llm-output-handling",
            "llm-sensitive-disclosure", "llm-system-prompt-leak",
            "llm-excessive-agency"],
    "auth": ["jwt-analysis", "jwt-weak-secret", "jwt-advanced-analysis",
             "auth-bypass-probe", "rate-limit-absent",
             "user-enumeration-timing", "cookie-flags-missing"],
    "infra": ["server-disclosure", "env-file-exposure",
              "js-bundle-secrets", "laravel-debug-mode",
              "cache-poisoning-probe", "http-methods-allowed"],
    "cloud": ["ssrf-cloud-metadata"],
    "temporal": ["race-condition-basic", "race-condition-authed",
                 "race-advanced", "idempotency-violation", "timing-vs-baseline"],
}


@dataclass
class CoverageReport:
    owasp: dict = field(default_factory=dict)
    attack_surfaces: dict = field(default_factory=dict)
    unrun_capabilities: list = field(default_factory=list)
    untested_categories: list = field(default_factory=list)
    executed_count: int = 0
    total_count: int = 0

    def to_dict(self):
        return {
            "owasp": self.owasp,
            "attack_surfaces": self.attack_surfaces,
            "unrun_capabilities": self.unrun_capabilities,
            "untested_categories": self.untested_categories,
            "executed_count": self.executed_count,
            "total_count": self.total_count,
        }


def _all_pattern_ids():
    try:
        return sorted({p["id"] for p in loader.list_patterns()})
    except Exception:
        return []


def _norm_executed(executed_caps):
    out = set()
    for cap in executed_caps or []:
        if isinstance(cap, str):
            out.add(cap)
        else:
            pid = getattr(cap, "pattern_id", None) or getattr(cap, "capability", None)
            if pid:
                out.add(pid)
    return out


def build_coverage_report(target=None, findings=None, executed_caps=None,
                          profile="standard", duration=None):
    executed = _norm_executed(executed_caps)
    if findings:
        for f in findings:
            pid = None
            if isinstance(f, dict):
                pid = f.get("pattern_id") or f.get("capability")
            else:
                pid = getattr(f, "pattern_id", None) or getattr(f, "capability", None)
            if pid:
                executed.add(pid)

    all_pids = _all_pattern_ids()
    total = len(all_pids)
    unrun = sorted([p for p in all_pids if p not in executed])

    owasp = {}
    for code in OWASP_CATEGORIES:
        expected = OWASP_TO_CAPABILITIES.get(code) or []
        covered = [p for p in expected if p in executed]
        missing = [p for p in expected if p not in executed]
        if expected:
            pct = round(100.0 * len(covered) / len(expected), 1)
        else:
            pct = 0.0
        owasp[code] = {
            "executed": covered,
            "missing": missing,
            "coverage_pct": pct,
            "covered": len(covered),
            "total": len(expected),
        }

    surfaces = {}
    for name, caps in ATTACK_SURFACES.items():
        covered = [c for c in caps if c in executed]
        missing = [c for c in caps if c not in executed]
        surfaces[name] = {
            "executed": covered,
            "missing": missing,
            "coverage_pct": round(100.0 * len(covered) / len(caps), 1) if caps else 0.0,
        }

    untested = [code for code in OWASP_CATEGORIES
                if not owasp[code]["executed"]]

    return CoverageReport(
        owasp=owasp,
        attack_surfaces=surfaces,
        unrun_capabilities=unrun,
        untested_categories=untested,
        executed_count=len(executed),
        total_count=total,
    ).to_dict()


def as_hypotheses(coverage_dict, target="", limit=20):
    from .state import Hypothesis
    untested = (coverage_dict or {}).get("untested_categories") or []
    out = []
    seen = set()
    for code in untested:
        for cap in (OWASP_TO_CAPABILITIES.get(code) or []):
            if cap in seen:
                continue
            seen.add(cap)
            out.append(Hypothesis(
                capability=cap, target=target,
                reason="coverage gap in " + str(code),
                priority=5, source="coverage_gap",
            ))
            if len(out) >= limit:
                return out
    return out


__all__ = [
    "CoverageReport", "build_coverage_report",
    "OWASP_TO_CAPABILITIES", "ATTACK_SURFACES", "OWASP_CATEGORIES",
    "as_hypotheses",
]



# ===========================================================================
# Phase 3 — add new capabilities to the OWASP and attack-surface maps.
# ===========================================================================
_PHASE3_COVERAGE_INSTALLED = True

_PHASE3_OWASP_CAPS = {
    "A01": ["open-redirect", "oauth-redirect-uri", "websocket-cswsh",
            "host-header-injection"],
    "A02": ["http2-desync", "crlf-injection", "host-header-injection"],
    "A05": ["ssti-probe", "xxe-probe", "nosql-probe",
            "second-order-xss", "timing-sqli", "timing-ssti", "timing-xxe",
            "open-redirect", "crlf-injection"],
    "A06": ["second-order-xss", "timing-sqli", "timing-ssti"],
    "A07": ["weak-password-policy", "lockout-probe",
            "weak-credential-enum", "oauth-missing-state",
            "oauth-redirect-uri"],
    "A08": ["upload-probe"],
    "A10": ["http2-desync", "host-header-injection"],
}

for _code, _caps in _PHASE3_OWASP_CAPS.items():
    _existing = OWASP_TO_CAPABILITIES.setdefault(_code, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)


_PHASE3_SURFACES = {
    "auth": ["oauth-missing-state", "oauth-redirect-uri",
             "weak-password-policy", "lockout-probe",
             "weak-credential-enum"],
    "injection": ["ssti-probe", "xxe-probe", "nosql-probe",
                  "crlf-injection", "host-header-injection",
                  "second-order-xss", "timing-sqli", "timing-ssti",
                  "timing-xxe"],
    "infra": ["http2-desync", "crlf-injection"],
    "rest": ["open-redirect", "upload-probe"],
}

for _name, _caps in _PHASE3_SURFACES.items():
    _existing = ATTACK_SURFACES.setdefault(_name, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)


_PHASE4_OWASP_CAPS = {
    "A01": ["access-bypass", "cache-deception"],
    "A03": ["cve-correlation"],
}

for _code, _caps in _PHASE4_OWASP_CAPS.items():
    _existing = OWASP_TO_CAPABILITIES.setdefault(_code, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)

_PHASE4_SURFACES = {
    "rest": ["access-bypass", "cache-deception"],
    "infra": ["cve-correlation"],
}

for _name, _caps in _PHASE4_SURFACES.items():
    _existing = ATTACK_SURFACES.setdefault(_name, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)


_PHASE5_OWASP_CAPS = {
    "A01": ["differential-auth"],
    "A02": ["wayback-mining"],
}

for _code, _caps in _PHASE5_OWASP_CAPS.items():
    _existing = OWASP_TO_CAPABILITIES.setdefault(_code, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)

_PHASE5_SURFACES = {
    "rest": ["differential-auth"],
    "infra": ["wayback-mining"],
}

for _name, _caps in _PHASE5_SURFACES.items():
    _existing = ATTACK_SURFACES.setdefault(_name, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)


_PHASE6_OWASP_CAPS = {
    "A05": ["framework-surface", "timing-robust"],
    "A02": ["framework-surface"],
}

for _code, _caps in _PHASE6_OWASP_CAPS.items():
    _existing = OWASP_TO_CAPABILITIES.setdefault(_code, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)

_PHASE6_SURFACES = {
    "infra": ["framework-surface"],
    "injection": ["timing-robust"],
}

for _name, _caps in _PHASE6_SURFACES.items():
    _existing = ATTACK_SURFACES.setdefault(_name, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)


_PHASE7_OWASP_CAPS = {
    "A08": ["deserialization"],
    "A01": ["graphql-schema-walk"],
    "A02": ["sourcemap-mining", "ct-subdomain"],
}

for _code, _caps in _PHASE7_OWASP_CAPS.items():
    _existing = OWASP_TO_CAPABILITIES.setdefault(_code, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)

_PHASE7_SURFACES = {
    "injection": ["deserialization"],
    "graphql": ["graphql-schema-walk"],
    "recon": ["sourcemap-mining", "ct-subdomain"],
}

for _name, _caps in _PHASE7_SURFACES.items():
    _existing = ATTACK_SURFACES.setdefault(_name, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)


_PHASE8_OWASP_CAPS = {
    "A08": ["subdomain-takeover"],
    "A01": ["cloud-storage"],
    "A05": ["hpp-scan"],
}

for _code, _caps in _PHASE8_OWASP_CAPS.items():
    _existing = OWASP_TO_CAPABILITIES.setdefault(_code, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)

_PHASE2_OWASP_CAPS = {
    "A01": ["bola-harvest", "unauth-pagination-dump",
            "graphql-data-dump", "llm-system-prompt-dump",
            "llm-tool-list-dump"],
    "A02": ["firebase-misconfig", "llm-credential-extract",
            "mcp-credential-exposure"],
    "A03": ["ci-cd-config-exposure", "npmrc-exposure"],
    "A05": ["blind-sqli-extract", "blind-xxe-file-read",
            "mcp-tool-poisoning", "postmessage-abuse"],
    "A07": ["session-fixation"],
}

for _code, _caps in _PHASE2_OWASP_CAPS.items():
    _existing = OWASP_TO_CAPABILITIES.setdefault(_code, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)


_PHASE2_SURFACES = {
    "rest": ["bola-harvest", "unauth-pagination-dump",
             "postmessage-abuse"],
    "graphql": ["graphql-data-dump"],
    "llm": ["llm-system-prompt-dump", "llm-tool-list-dump",
            "llm-credential-extract", "mcp-tool-poisoning",
            "mcp-credential-exposure"],
    "auth": ["session-fixation"],
    "infra": ["ci-cd-config-exposure", "npmrc-exposure",
              "firebase-misconfig"],
    "injection": ["blind-sqli-extract", "blind-xxe-file-read"],
}

for _name, _caps in _PHASE2_SURFACES.items():
    _existing = ATTACK_SURFACES.setdefault(_name, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)


_PHASE8_SURFACES = {
    "recon": ["subdomain-takeover", "cloud-storage"],
    "injection": ["hpp-scan"],
}

for _name, _caps in _PHASE8_SURFACES.items():
    _existing = ATTACK_SURFACES.setdefault(_name, [])
    for _c in _caps:
        if _c not in _existing:
            _existing.append(_c)
