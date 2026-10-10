Gap 1: No AI/LLM Security Testing (Highest Priority)
What's missing: Your tool has zero coverage for OWASP LLM Top 10 (2025) categories: prompt injection, sensitive information disclosure from LLMs, supply chain attacks on models, excessive agency, system prompt leakage, vector/embedding weaknesses, and multi-turn adversarial attacks.

Why this matters: As of 2026, AI-powered agents are being deployed without the equivalent of npm audit — the industry is actively building tools like agent-redteam (2,304 test samples across 14 attack suites) and ASTRA (140 adversarial attacks across 10 real-world scenarios) to fill this gap. If your target is an AI-enabled application, you're blind to its most critical attack surface.

What to add:

Prompt injection detection: Inject adversarial prompts into user-controlled inputs and observe whether the LLM executes unintended actions (tool abuse, data exfiltration).

Tool abuse probing: Test whether the agent can be manipulated into calling destructive tools (rm -rf, DROP TABLE) via crafted prompts.

System prompt extraction: Attempt to leak the system prompt through role-play, encoding tricks, or context manipulation.

Multi-turn attacks: Establish trust over multiple interactions before escalating.

Vector/embedding isolation testing: Verify tenant isolation in RAG systems.

Implementation approach: Add a new adapter type (ai_agent.yaml) and a new oracle family (llm_security). Payload templates should be stored in wordlists and injected via the existing HTTP client. The OOB server can detect exfiltration callbacks.

Gap 2: No Supply Chain / SCA Scanning
What's missing: OWASP Top 10 2025 elevated Software Supply Chain Failures to A03 — the first time it entered the top three. Your tool has no capability to analyze dependencies, detect vulnerable packages, or generate an SBOM.

Why this matters: The 2025 400% spike in critical API vulnerabilities continued into 2026, with supply chain issues driving critical counts. SCA tools themselves are under scrutiny — a 2025 study found many perform like "limited-use toys" under real-world conditions due to multi-language ecosystem gaps and binary dependency blindness.

What to add:

Dependency file detection: Scan for package.json, requirements.txt, composer.json, Gemfile, pom.xml, go.mod, Cargo.toml, etc.

Known-vulnerability lookup: Cross-reference detected versions against OSV.dev, GitHub Advisory Database, or NVD.

Typosquatting detection: Flag packages with names suspiciously similar to popular ones (e.g., reqeusts vs requests).

SBOM generation: Output CycloneDX or SPDX format for downstream analysis.

CI/CD pipeline attack surface: Detect exposed .github/workflows/, .gitlab-ci.yml, Jenkinsfiles.

Implementation approach: Add a sca command and a supply_chain oracle. Use OSV.dev's free API for vulnerability lookups. This complements your existing secret-scanning patterns.

Gap 3: JWT Testing is Incomplete
What's missing: Your jwt-weak-secret pattern only brute-forces HMAC secrets. You're missing algorithm confusion (RS256→HS256 with public key), kid parameter injection, none algorithm acceptance, and timestamp confusion — all of which are actively exploited in 2025–2026.

Why this matters: Detectify added a full API testing category specifically for JWT misconfigurations in late 2025, noting that algorithm confusion is "one of the most critical JWT vulnerabilities". Tools like jwt-scanner and jwt_tool systematically test all attack vectors.

What to add:

Algorithm confusion probe: If the target uses RS256, re-sign the token as HS256 using the public key text as the HMAC secret.

none algorithm probe: Strip the signature and set alg: none — check if the server accepts it.

kid injection: Test for path traversal or SQL injection in the kid header parameter.

Timestamp manipulation: Modify exp, iat, nbf claims to test validation logic.

JKU/X5U header injection: Test whether the server fetches keys from an attacker-controlled URL.

Implementation approach: Extend oracle.py with a jwt_advanced oracle type. Reuse your existing \_collect_jwts() extraction logic.

Gap 4: No GraphQL Deep Security Testing
What's missing: Your graphql-introspection pattern is a single oracle. You're missing query depth limit bypass, batch query abuse, field suggestion exploitation, CSRF via form-encoded GraphQL, and access control bypass on interfaces (CVE-2025-64530).

Why this matters: Apollo Federation had multiple access control bypass CVEs in 2025. GraphQL Armor's max-depth plugin has known bypasses via introspection query obfuscation. A misconfigured GraphQL endpoint accepting application/x-www-form-urlencoded enables CSRF.

What to add:

Depth limit bypass: Send deeply nested queries (100+ levels) and check if they complete.

Batching attack: Send 100+ queries in a single request to bypass rate limiting.

Form-encoded CSRF probe: POST GraphQL queries as application/x-www-form-urlencoded.

Interface directive bypass: If Apollo Federation is detected, test for the CVE-2025-64530 pattern.

Field suggestion enumeration: Send queries with typos and harvest did you mean suggestions to enumerate the schema even when introspection is disabled.

Gap 5: Race Condition Testing is Simplistic
What's missing: Your race-condition-basic pattern uses concurrency: 20 with a simple state_inconsistent oracle. Modern race condition testing requires sub-microsecond timing precision, barrier synchronization, and single-packet attacks (HTTP/2 and HTTP/3).

Why this matters: Tools like TRECO achieve race windows under 1μs with barrier synchronization. Racey exploits the "single packet attack" technique to send multiple requests simultaneously. Your thread-pool approach cannot achieve this precision.

What to add:

HTTP/2 single-packet attack: Send multiple requests in a single TCP packet using HTTP/2 multiplexing.

Barrier synchronization: Use threading barriers to fire requests at the exact same moment.

Timing histogram analysis: Measure the distribution of response times to detect exploitable windows.

State machine probing: Send requests that violate expected state transitions.

Gap 6: DOM-Based XSS Not Properly Detected
What's missing: Your xss command uses browser.capture() with OOB callbacks, which detects reflected and stored XSS. DOM-based XSS requires taint tracking through JavaScript sinks (innerHTML, eval, document.write), which your tool doesn't perform.

What to add:

Source/sink analysis: Inject payloads that flow through DOM sources (location.hash, document.referrer, window.name) and check if they reach dangerous sinks.

Trusted Types detection: Check if the target has CSP require-trusted-types-for 'script' and whether it's bypassable.

Mutation XSS (mXSS): Test payloads that are safe after initial parsing but dangerous after browser re-serialization.

Gap 7: SSRF Lacks Cloud Metadata Exploitation
What's missing: Your SSRF probe tests for OOB callbacks but doesn't specifically target cloud metadata endpoints (169.254.169.254, metadata.google.internal, Azure IMDS). This is the highest-impact SSRF exploitation path — a single SSRF can pivot to full cloud account compromise.

What to add:

AWS IMDSv1/v2 probing: Test both direct access and IMDSv2 session-token bypass techniques.

GCP metadata: Probe metadata.google.internal with Metadata-Flavor: Google header.

Azure IMDS: Probe 169.254.169.254/metadata/instance with Metadata: true header.

Kubernetes service account tokens: Test /var/run/secrets/kubernetes.io/serviceaccount/token.

Protocol smuggling: Test gopher://, dict://, file:// schemes.

Gap 8: No OpenAPI/Swagger-Driven Testing
What's missing: Your tool discovers API paths from JavaScript bundles but doesn't parse OpenAPI/Swagger specifications to generate targeted tests. This is a major efficiency gap — an OpenAPI spec gives you every endpoint, method, parameter, and schema.

What to add:

Spec discovery: Probe for /openapi.json, /swagger.json, /api-docs, /v3/api-docs.

Parameter fuzzing from schema: Generate type-specific payloads (integer overflow, string injection, boolean flipping) based on schema definitions.

Authentication scheme detection: Identify security schemes (bearerAuth, apiKey, oauth2) and automatically configure auth probes.

Endpoint coverage report: Compare tested endpoints against spec-defined endpoints.

Gap 9: No Business Logic Flaw Detection
What's missing: OWASP 2025 emphasizes that traditional scanners "struggle to detect complex business logic flaws". Your pattern-based approach cannot detect flaws like price manipulation, coupon abuse, workflow bypass, or privilege escalation through multi-step processes.

What to add:

Multi-step workflow recording: Use Playwright to record user workflows, then replay with modified parameters.

Parameter tampering: Identify business-critical parameters (price, quantity, role) and test boundary values.

Workflow bypass: Skip mandatory steps (e.g., payment step in checkout) and check if the final state is reachable.

Race-condition-gated logic: Combine race testing with business logic probes (e.g., apply coupon twice simultaneously).

Gap 10: No Compliance Mapping to OWASP Top 10 2025
What's missing: Your findings map to WSTG and CWE, but not to OWASP Top 10 2025. The 2025 list has new categories (Software Supply Chain Failures, Mishandling of Exceptional Conditions) and merged categories (SSRF into Broken Access Control).

What to add:

OWASP Top 10 2025 mapping: Tag every pattern with its OWASP 2025 category.

Compliance report: Generate a report showing coverage against OWASP Top 10 2025, with gaps highlighted.

Severity recalibration: Align severity scores with OWASP 2025 risk rankings.
