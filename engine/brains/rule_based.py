from ..state import Hypothesis, ScanState, TriageDecision


FRAMEWORK_HINTS = {
    "laravel": [
        "laravel-debug-mode",
        "env-file-exposure",
        "security-headers-missing",
        "cors-wildcard",
        "rate-limit-absent",
        "auth-bypass-probe",
    ],
    "django": [
        "security-headers-missing",
        "env-file-exposure",
        "cors-wildcard",
        "rate-limit-absent",
    ],
    "rails": [
        "security-headers-missing",
        "env-file-exposure",
        "cors-wildcard",
    ],
    "nextjs": [
        "security-headers-missing",
        "cors-wildcard",
        "jwt-analysis",
    ],
    "nuxt": [
        "security-headers-missing",
        "cors-wildcard",
    ],
    "spring_boot": [
        "security-headers-missing",
        "cors-wildcard",
    ],
    "express": [
        "security-headers-missing",
        "cors-wildcard",
    ],
    "fastapi": [
        "security-headers-missing",
        "cors-wildcard",
        "jwt-analysis",
    ],
    "wordpress": [
        "security-headers-missing",
        "cors-wildcard",
    ],
    "aspnet": [
        "security-headers-missing",
        "cors-wildcard",
    ],
    "ai_agent": [
        "llm-prompt-injection",
        "llm-output-handling",
        "llm-sensitive-disclosure",
        "llm-system-prompt-leak",
        "llm-excessive-agency",
    ],
}


ENDPOINT_HINTS = {
    "/graphql": ["graphql-deep-security", "graphql-introspection"],
    "/login": [
        "rate-limit-absent",
        "user-enumeration-timing",
        "auth-bypass-probe",
    ],
    "/api/login": ["rate-limit-absent", "user-enumeration-timing"],
    "/api/auth": ["jwt-analysis", "jwt-weak-secret"],
    "/api/me": ["auth-bypass-probe"],
    "/api/users": ["idor-sequential", "authed-idor"],
    "/openapi": ["openapi-fuzz"],
    "/swagger": ["openapi-fuzz"],
}


EXTRACTION_TOOLS = [
    "unauth-pagination-dump",
    "graphql-data-dump",
    "bola-harvest",
    "llm-system-prompt-dump",
    "llm-tool-list-dump",
]


RELATED_CAPABILITIES = {
    "env-file-exposure": ["mass-assignment", "jwt-weak-secret"],
    "cors-wildcard": ["api-cors-preflight", "cookie-flags-missing"],
    "auth-bypass-probe": ["idor-sequential", "authed-idor"],
    "idor-sequential": ["mass-assignment"],
    "jwt-weak-secret": ["authed-idor", "jwt-advanced-analysis"],
    "server-disclosure": ["laravel-debug-mode"],
    "security-headers-missing": ["dom-xss-advanced"],
    "graphql-introspection": ["graphql-deep-security"],
    "llm-prompt-injection": ["llm-excessive-agency"],
    "api-cors-preflight": ["cookie-flags-missing"],
}


class RuleBasedBrain:
    def __init__(self, max_per_iter=20):
        self.max_per_iter = max_per_iter

    def _framework_caps(self, state):
        fw = ((state.framework or {}).get("adapter") or {}).get("id") or ""
        return list(FRAMEWORK_HINTS.get(fw, []))

    def _endpoint_caps(self, state):
        caps = []
        for ep in state.discovered_endpoints or []:
            epl = str(ep).lower()
            for prefix, hints in ENDPOINT_HINTS.items():
                if prefix in epl:
                    caps.extend(hints)
        return caps

    def _extraction_hints(self, state):
        out = []
        for cap in EXTRACTION_TOOLS:
            if cap not in state.executed_capabilities:
                out.append(cap)
        return out[:3]

    def _cross_finding_caps(self, state):
        caps = []
        for f in state.findings or []:
            cap = getattr(f, "capability", None)
            v = getattr(f, "verdict", None)
            if hasattr(v, "value"):
                v = v.value
            if v in ("VULNERABLE", "SUSPICIOUS"):
                caps.extend(RELATED_CAPABILITIES.get(cap, []))
        return caps

    def propose(self, state):
        caps = set()
        caps.update(self._framework_caps(state))
        caps.update(self._endpoint_caps(state))
        caps.update(self._cross_finding_caps(state))
        if not caps:
            caps.update(["security-headers-missing", "cors-wildcard"])
        if len(caps) < 3:
            caps.update(self._extraction_hints(state))
        caps = {c for c in caps if c not in state.executed_capabilities}
        hypotheses = [
            Hypothesis(
                capability=c,
                target=state.target,
                source="rule_based",
                priority=10,
                reason="matched rule",
            )
            for c in sorted(caps)
        ]
        return hypotheses[:self.max_per_iter]

    def triage(self, finding):
        return TriageDecision(keep=True)

    def triage_finding(self, finding):
        return TriageDecision(keep=True, escalate=True,
                              reason="no LLM — kept for human review")

    def should_stop(self, state):
        return False

    def can_author_payload(self, capability):
        return False

    def propose_payload(self, state, capability):
        return None

    def triage_response(self, baseline, candidate, context=None):
        return _rule_triage(baseline, candidate, context)


def _extract_field(obj, name):
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _rule_triage(baseline, candidate, context=None):
    if baseline is None or candidate is None:
        return TriageDecision(keep=True, reason="missing baseline or candidate")

    b_status = _extract_field(baseline, "status")
    c_status = _extract_field(candidate, "status")
    b_len = _extract_field(baseline, "body_len")
    c_len = _extract_field(candidate, "body_len")
    b_hash = _extract_field(baseline, "structural_hash")
    c_hash = _extract_field(candidate, "structural_hash")

    if b_status is not None and c_status is not None and b_status != c_status:
        return TriageDecision(
            keep=True, escalate=True,
            reason="status " + str(b_status) + " -> " + str(c_status))

    if b_len and c_len and b_len > 0:
        delta_pct = abs(c_len - b_len) / b_len
        if delta_pct > 0.2:
            return TriageDecision(
                keep=True, escalate=True,
                reason="body_len delta " + str(round(delta_pct, 2)))

    if b_hash and c_hash and b_hash != c_hash:
        return TriageDecision(
            keep=True, escalate=False,
            reason="hash differs but length stable")

    return TriageDecision(
        keep=True, escalate=False,
        reason="no significant difference")


__all__ = ["RuleBasedBrain"]
