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
    {
        "id": "auto-env-plus-cve",
        "name": "Env Leak + Known CVE on Detected Component",
        "requires": ["env-file-exposure", "cve-correlation"],
        "severity": "critical",
        "narrative": ("Env file leaks APP_KEY and DB credentials. The "
                      "detected runtime version is affected by a public CVE. "
                      "Combined: local secrets plus a documented remote "
                      "exploit path."),
    },
    {
        "id": "auto-cors-plus-cache-deception",
        "name": "CORS Wildcard + Web Cache Deception",
        "requires": ["cors-wildcard", "cache-deception"],
        "severity": "high",
        "narrative": ("Cache deception caches the authenticated response at "
                      "a guessable URL. CORS wildcard lets any origin read "
                      "it once the victim loads the attacker page."),
    },
    {
        "id": "auto-bypass-plus-idor",
        "name": "403 Bypass + Authenticated IDOR",
        "requires": ["access-bypass", "authed-idor"],
        "severity": "critical",
        "narrative": ("The 403 gate guarding a resource is bypassed via "
                      "header override or path mutation. Authenticated IDOR "
                      "on the same surface walks every record behind it."),
    },
    {
        "id": "auto-bola-plus-jwt-forge",
        "name": "BOLA + Forged JWT = Complete Account Takeover",
        "requires": ["bola-harvest", "jwt-weak-secret"],
        "severity": "critical",
        "narrative": ("Weak JWT secret cracked offline, then reused to forge "
                      "tokens for any sub. BOLA harvester walks the ID space "
                      "and dumps every account."),
    },
    {
        "id": "auto-graphql-dump-plus-idor",
        "name": "GraphQL Dump + Authenticated IDOR",
        "requires": ["graphql-data-dump", "authed-idor"],
        "severity": "critical",
        "narrative": ("Schema introspection exposes every object type. "
                      "IDOR lets the attacker walk every record of each type."),
    },
    {
        "id": "auto-blind-sqli-plus-weak-password",
        "name": "Blind SQLi Dump + Weak Password Policy",
        "requires": ["blind-sqli-extract", "weak-password-policy"],
        "severity": "critical",
        "narrative": ("Blind SQLi reconstructs the users table, including "
                      "hashes. Weak policy means the hashes crack on the "
                      "first dictionary pass."),
    },
    {
        "id": "auto-xxe-plus-cloud-metadata",
        "name": "XXE File Read + Cloud Metadata",
        "requires": ["blind-xxe-file-read", "ssrf-cloud-metadata"],
        "severity": "critical",
        "narrative": ("XXE reaches server files (env, keys). Cloud metadata "
                      "SSRF reaches IAM credentials. Together: full cloud "
                      "account compromise."),
    },
    {
        "id": "auto-llm-prompt-plus-credentials",
        "name": "LLM System Prompt + Credential Extraction",
        "requires": ["llm-system-prompt-dump", "llm-credential-extract"],
        "severity": "critical",
        "narrative": ("System prompt recovered, then used to steer the model "
                      "into outputting its own credentials."),
    },
    {
        "id": "auto-llm-tools-plus-agency",
        "name": "LLM Tool List + Excessive Agency",
        "requires": ["llm-tool-list-dump", "llm-excessive-agency"],
        "severity": "critical",
        "narrative": ("Tool schema disclosed, then the model is directed to "
                      "invoke a high-privilege tool with attacker args."),
    },
    {
        "id": "auto-mcp-poison-plus-creds",
        "name": "MCP Tool Poisoning + Credential Exposure",
        "requires": ["mcp-tool-poisoning", "mcp-credential-exposure"],
        "severity": "critical",
        "narrative": ("A poisoned MCP tool description redirects the agent "
                      "into reading a config file that itself contains live "
                      "credentials."),
    },
    {
        "id": "auto-cicd-plus-cve",
        "name": "CI/CD Config + Known CVE",
        "requires": ["ci-cd-config-exposure", "cve-correlation"],
        "severity": "critical",
        "narrative": ("Pipeline config leaks deploy tokens and image tags. "
                      "A CVE on the same component turns the leak into RCE."),
    },
    {
        "id": "auto-npmrc-plus-cve",
        "name": "Registry Token + Known CVE",
        "requires": ["npmrc-exposure", "cve-correlation"],
        "severity": "high",
        "narrative": ("Package-manager config leaks registry tokens. A CVE "
                      "on the same package lets the attacker poison the "
                      "next release."),
    },
    {
        "id": "auto-firebase-plus-session-fix",
        "name": "Firebase Misconfig + Session Fixation",
        "requires": ["firebase-misconfig", "session-fixation"],
        "severity": "critical",
        "narrative": ("Firebase accepts unauthenticated reads. Session ID "
                      "is not rotated on login. Combined: mass data dump "
                      "plus durable session hijack."),
    },
    {
        "id": "auto-session-fix-plus-jwt",
        "name": "Session Fixation + Forged JWT",
        "requires": ["session-fixation", "jwt-weak-secret"],
        "severity": "critical",
        "narrative": ("Session ID not rotated, and the JWT secret is weak. "
                      "Attacker fixes a session, victim logs in, attacker "
                      "reuses it with a forged token."),
    },
    {
        "id": "auto-pagination-plus-idor",
        "name": "Unauth Pagination Dump + Sequential IDOR",
        "requires": ["unauth-pagination-dump", "idor-sequential"],
        "severity": "critical",
        "narrative": ("Unauthenticated pagination yields the full dataset. "
                      "Sequential IDOR reaches the same records by direct "
                      "ID for higher fidelity."),
    },
    {
        "id": "auto-postmessage-plus-domxss",
        "name": "PostMessage Abuse + DOM XSS",
        "requires": ["postmessage-abuse", "dom-xss-advanced"],
        "severity": "high",
        "narrative": ("Missing origin check on postMessage lets any page "
                      "control the target. A DOM XSS sink renders the "
                      "injected payload."),
    },
    {
        "id": "auto-blind-sqli-plus-mcp",
        "name": "Blind SQLi Dump + MCP Credential Exposure",
        "requires": ["blind-sqli-extract", "mcp-credential-exposure"],
        "severity": "critical",
        "narrative": ("DB blind extraction returns the users table. MCP "
                      "config exposes live credentials. Both point at the "
                      "same operator account."),
    },
    {
        "id": "auto-graphql-plus-llm-prompt",
        "name": "GraphQL Dump + LLM System Prompt",
        "requires": ["graphql-data-dump", "llm-system-prompt-dump"],
        "severity": "high",
        "narrative": ("Full API surface exposed via GraphQL. LLM system "
                      "prompt leaks the internal data model and API keys."),
    },
    {
        "id": "auto-bola-plus-differential",
        "name": "BOLA Harvest + Cross-Auth Differential",
        "requires": ["bola-harvest", "differential-auth"],
        "severity": "critical",
        "narrative": ("BOLA confirms cross-user read. Differential auth "
                      "confirms the same anomaly from an independent probe, "
                      "eliminating false-positive doubt."),
    },
    {
        "id": "auto-bypass-plus-graphql-dump",
        "name": "403 Bypass + GraphQL Data Dump",
        "requires": ["access-bypass", "graphql-data-dump"],
        "severity": "critical",
        "narrative": ("Header override bypasses the 403 on /graphql. Full "
                      "introspection then dumps every record the schema "
                      "exposes."),
    },
    {
        "id": "auto-cache-plus-bola",
        "name": "Cache Deception + BOLA Harvest",
        "requires": ["cache-deception", "bola-harvest"],
        "severity": "critical",
        "narrative": ("Cache deception caches one victim's private response "
                      "at a guessable URL. BOLA harvest scales the same "
                      "attack across the ID space."),
    },
    {
        "id": "auto-mcp-plus-llm-prompt",
        "name": "MCP Tool Poisoning + LLM Prompt Dump",
        "requires": ["mcp-tool-poisoning", "llm-system-prompt-dump"],
        "severity": "critical",
        "narrative": ("Poisoned MCP tool description plus a system prompt "
                      "that leaks guardrails gives the attacker full agent "
                      "control."),
    },
    {
        "id": "auto-cloud-bucket-plus-cicd",
        "name": "Cloud Bucket + CI/CD Config",
        "requires": ["cloud-storage", "ci-cd-config-exposure"],
        "severity": "critical",
        "narrative": ("Public bucket serves the CI config. The CI config "
                      "contains deploy credentials. Deploy credentials write "
                      "to production."),
    },
    {
        "id": "auto-sourcemap-plus-info-disclosure",
        "name": "Sourcemap Mining + API Info Disclosure",
        "requires": ["sourcemap-mining", "api-info-disclosure"],
        "severity": "high",
        "narrative": ("Source maps recover original source. Error bodies "
                      "leak file paths and class names. Together: code "
                      "reconstruction plus internal layout."),
    },
    {
        "id": "auto-takeover-plus-cookies",
        "name": "Subdomain Takeover + Missing Cookie Flags",
        "requires": ["subdomain-takeover", "cookie-flags-missing"],
        "severity": "critical",
        "narrative": ("Takeover of one subdomain plus cookies that lack "
                      "HttpOnly/Secure: the hijacked page reads the parent "
                      "session cookie and exfiltrates it."),
    },
    {
        "id": "auto-framework-surface-plus-cve",
        "name": "Framework Surface + CVE on Same Component",
        "requires": ["framework-surface", "cve-correlation"],
        "severity": "critical",
        "narrative": ("A vulnerable framework surface (debug endpoint, "
                      "management path) is exposed, and a public CVE for "
                      "the detected version matches that surface."),
    },
    {
        "id": "auto-deser-plus-jwt",
        "name": "Unsafe Deserialization + Forged JWT",
        "requires": ["deserialization", "jwt-weak-secret"],
        "severity": "critical",
        "narrative": ("Deserializer accepts magic bytes and errors loudly. "
                      "Weak JWT secret lets the attacker sign a token that "
                      "passes the same authorization gate."),
    },
    {
        "id": "auto-hpp-plus-mass-assign",
        "name": "HPP + Mass Assignment",
        "requires": ["hpp-scan", "mass-assignment"],
        "severity": "high",
        "narrative": ("Parameter pollution lets the attacker smuggle a "
                      "second role=admin past a WAF that only inspects the "
                      "first value. Mass assignment accepts it."),
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
