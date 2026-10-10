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

    def should_stop(self, state):
        return False

    def can_author_payload(self, capability):
        return False

    def propose_payload(self, state, capability):
        return None


__all__ = ["RuleBasedBrain"]
