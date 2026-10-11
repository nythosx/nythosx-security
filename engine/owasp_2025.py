import json
import re
from collections import defaultdict


CATEGORIES = {
    "A01": {
        "code": "A01:2025",
        "name": "Broken Access Control",
        "short": "BAC",
        "rank": 1,
        "cwe_ids": ["CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200",
                    "CWE-201", "CWE-219", "CWE-264", "CWE-275", "CWE-276",
                    "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377",
                    "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538",
                    "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601",
                    "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862",
                    "CWE-863", "CWE-913", "CWE-922", "CWE-918"],
        "baseline_severity": "critical",
        "description": "Users acting outside intended permissions, including "
                       "IDOR, privilege escalation, forced browsing, CORS "
                       "misconfig, JWT/cookie tampering, and SSRF (merged in "
                       "from 2021 A10).",
    },
    "A02": {
        "code": "A02:2025",
        "name": "Security Misconfiguration",
        "short": "Misconfig",
        "rank": 2,
        "cwe_ids": ["CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16",
                    "CWE-260", "CWE-315", "CWE-489", "CWE-497", "CWE-526",
                    "CWE-547", "CWE-611", "CWE-614", "CWE-756", "CWE-776",
                    "CWE-942", "CWE-1004", "CWE-1174"],
        "baseline_severity": "high",
        "description": "Insecure defaults, verbose errors, unhardened "
                       "cloud/container settings, missing security headers, "
                       "and exposed debug interfaces.",
    },
    "A03": {
        "code": "A03:2025",
        "name": "Software Supply Chain Failures",
        "short": "SupplyChain",
        "rank": 3,
        "cwe_ids": ["CWE-1035", "CWE-1104", "CWE-1327", "CWE-1357",
                    "CWE-1395", "CWE-1426"],
        "baseline_severity": "critical",
        "description": "Compromise across the software delivery chain: "
                       "vulnerable dependencies, build systems, distribution "
                       "infrastructure, unsigned/unverified artifacts, and "
                       "abandoned/unmaintained components.",
    },
    "A04": {
        "code": "A04:2025",
        "name": "Cryptographic Failures",
        "short": "Crypto",
        "rank": 4,
        "cwe_ids": ["CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-320",
                    "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325",
                    "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330",
                    "CWE-331", "CWE-332", "CWE-334", "CWE-335", "CWE-336",
                    "CWE-337", "CWE-338", "CWE-340", "CWE-342", "CWE-347",
                    "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760",
                    "CWE-780", "CWE-916", "CWE-1240"],
        "baseline_severity": "high",
        "description": "Weak or misused cryptography exposing sensitive data: "
                       "weak hash/cipher, missing TLS, exposed keys, "
                       "predictable randomness, and weak JWT signing.",
    },
    "A05": {
        "code": "A05:2025",
        "name": "Injection",
        "short": "Injection",
        "rank": 5,
        "cwe_ids": ["CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78",
                    "CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-88",
                    "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94",
                    "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99",
                    "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-470",
                    "CWE-471", "CWE-564", "CWE-610", "CWE-643", "CWE-644",
                    "CWE-652", "CWE-917"],
        "baseline_severity": "critical",
        "description": "User-controlled data enters an interpreter (SQL, "
                       "shell, HTML/JS, template engine, XML, LDAP, XPath). "
                       "Includes XSS, SQLi, SSTI, XXE, prompt injection.",
    },
    "A06": {
        "code": "A06:2025",
        "name": "Insecure Design",
        "short": "Design",
        "rank": 6,
        "cwe_ids": ["CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235",
                    "CWE-256", "CWE-266", "CWE-269", "CWE-280", "CWE-311",
                    "CWE-312", "CWE-313", "CWE-316", "CWE-362", "CWE-382",
                    "CWE-419", "CWE-434", "CWE-436", "CWE-444", "CWE-454",
                    "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539",
                    "CWE-579", "CWE-598", "CWE-602", "CWE-620", "CWE-640",
                    "CWE-646", "CWE-653", "CWE-656", "CWE-657", "CWE-693",
                    "CWE-799", "CWE-807", "CWE-840", "CWE-841", "CWE-1021"],
        "baseline_severity": "high",
        "description": "Design and architecture flaws: missing threat "
                       "modeling, business-logic abuse, race conditions, "
                       "workflow bypass, weak state machines, and "
                       "inadequate trust boundaries.",
    },
    "A07": {
        "code": "A07:2025",
        "name": "Authentication Failures",
        "short": "Auth",
        "rank": 7,
        "cwe_ids": ["CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290",
                    "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302",
                    "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384",
                    "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798",
                    "CWE-940", "CWE-1216"],
        "baseline_severity": "critical",
        "description": "Broken authentication: weak credential policies, "
                       "missing MFA, session fixation, credential stuffing, "
                       "user enumeration, missing rate limiting, and JWT "
                       "signature bypass.",
    },
    "A08": {
        "code": "A08:2025",
        "name": "Software or Data Integrity Failures",
        "short": "Integrity",
        "rank": 8,
        "cwe_ids": ["CWE-345", "CWE-346", "CWE-353", "CWE-426", "CWE-494",
                    "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830",
                    "CWE-915"],
        "baseline_severity": "high",
        "description": "Trusting unverified code or data: insecure "
                       "deserialization, unsigned software updates, "
                       "CI/CD integrity gaps, and mass assignment via "
                       "deserialization.",
    },
    "A09": {
        "code": "A09:2025",
        "name": "Security Logging & Alerting Failures",
        "short": "Logging",
        "rank": 9,
        "cwe_ids": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "baseline_severity": "medium",
        "description": "Insufficient logging, monitoring, and alerting: no "
                       "audit trail, silent failures, unactionable alerts, "
                       "and log injection. Renamed from 'Monitoring' to "
                       "'Alerting' in 2025.",
    },
    "A10": {
        "code": "A10:2025",
        "name": "Mishandling of Exceptional Conditions",
        "short": "Exceptions",
        "rank": 10,
        "cwe_ids": ["CWE-209", "CWE-234", "CWE-248", "CWE-252", "CWE-274",
                    "CWE-280", "CWE-390", "CWE-391", "CWE-392", "CWE-394",
                    "CWE-395", "CWE-396", "CWE-397", "CWE-431", "CWE-476",
                    "CWE-478", "CWE-484", "CWE-544", "CWE-617", "CWE-636",
                    "CWE-703", "CWE-754", "CWE-755", "CWE-756"],
        "baseline_severity": "medium",
        "description": "NEW IN 2025. Improper error handling, failing open, "
                       "unhandled exceptions, NULL dereferences, resource "
                       "exhaustion during exceptional conditions, and "
                       "verbose error leakage of sensitive information.",
    },
}


PATTERN_MAP = {
    "env-file-exposure": "A02",
    "js-bundle-secrets": "A02",
    "laravel-debug-mode": "A02",
    "api-exposed-headers": "A02",
    "authed-security-headers": "A02",
    "security-headers-missing": "A02",
    "server-disclosure": "A02",
    "http-methods-allowed": "A02",
    "graphql-introspection": "A02",
    "cache-poisoning-probe": "A02",
    "llm-sensitive-disclosure": "A02",
    "api-error-handling": "A10",
    "api-info-disclosure": "A10",
    "auth-bypass-probe": "A01",
    "authed-idor": "A01",
    "idor-sequential": "A01",
    "mass-assignment": "A01",
    "cors-wildcard": "A01",
    "api-cors-preflight": "A01",
    "ssrf-cloud-metadata": "A01",
    "llm-system-prompt-leak": "A01",
    "llm-excessive-agency": "A01",
    "dom-xss-advanced": "A05",
    "llm-prompt-injection": "A05",
    "llm-output-handling": "A05",
    "graphql-deep-security": "A05",
    "jwt-analysis": "A07",
    "jwt-weak-secret": "A07",
    "jwt-advanced-analysis": "A07",
    "rate-limit-absent": "A07",
    "user-enumeration-timing": "A07",
    "cookie-flags-missing": "A07",
    "timing-vs-baseline": "A07",
    "race-advanced": "A06",
    "race-condition-authed": "A06",
    "race-condition-basic": "A06",
    "bizlogic-scan": "A06",
    "idempotency-violation": "A06",
    "sca-scan": "A03",
    "openapi-fuzz": "A08",
    "workflow-tamper": "A06",
}


PREFIX_MAP = [
    ("sca-", "A03"),
    ("llm-prompt-", "A05"),
    ("llm-output-", "A05"),
    ("llm-system-prompt", "A01"),
    ("llm-sensitive", "A02"),
    ("llm-excessive", "A01"),
    ("llm-", "A02"),
    ("jwt-", "A07"),
    ("graphql-", "A05"),
    ("dom-xss", "A05"),
    ("domxss", "A05"),
    ("race-", "A06"),
    ("bizlogic-", "A06"),
    ("workflow-", "A06"),
    ("ssrf-cloud", "A01"),
    ("openapi-", "A08"),
    ("idor-", "A01"),
    ("cors-", "A01"),
    ("cookie-", "A07"),
    ("rate-limit-", "A07"),
    ("api-error-", "A10"),
    ("api-info-", "A10"),
    ("server-disclosure", "A02"),
    ("security-headers", "A02"),
    ("authed-security", "A02"),
    ("http-methods", "A02"),
    ("cache-poisoning", "A02"),
    ("env-file", "A02"),
    ("js-bundle", "A02"),
    ("laravel-debug", "A02"),
]


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _severity_rank(sev):
    try:
        return SEVERITY_ORDER.index((sev or "info").lower())
    except ValueError:
        return 0


def _severity_max(a, b):
    return a if _severity_rank(a) >= _severity_rank(b) else b


def map_pattern(pattern_id):
    if not pattern_id:
        return None
    pid = str(pattern_id)
    if pid in PATTERN_MAP:
        return PATTERN_MAP[pid]
    low = pid.lower()
    for prefix, cat in PREFIX_MAP:
        if low.startswith(prefix):
            return cat
    return None


def get_category(code_or_pattern):
    if not code_or_pattern:
        return None
    s = str(code_or_pattern)
    if s in CATEGORIES:
        return CATEGORIES[s]
    if s.startswith("A") and ":" in s:
        key = s.split(":", 1)[0]
        return CATEGORIES.get(key)
    mapped = map_pattern(s)
    if mapped:
        return CATEGORIES.get(mapped)
    return None


def recalibrate_severity(pattern_id, original_severity):
    cat = get_category(pattern_id)
    if not cat:
        return original_severity, None
    floor = cat.get("baseline_severity", "info")
    if _severity_rank(original_severity) < _severity_rank(floor):
        return floor, {
            "original": original_severity,
            "recalibrated": floor,
            "reason": f"raised to {floor} floor for {cat['code']} ({cat['name']})",
        }
    return original_severity, None


def coverage(findings):
    by_cat = defaultdict(list)
    unmapped = []
    for f in findings:
        pid = f.get("pattern_id") or f.get("id") or ""
        cat = map_pattern(pid)
        if cat:
            by_cat[cat].append(f)
        else:
            unmapped.append({"pattern_id": pid, "reason": "no OWASP 2025 mapping"})

    out = {}
    for code, cat in CATEGORIES.items():
        cat_findings = by_cat.get(code) or []
        verdicts = defaultdict(int)
        severities = defaultdict(int)
        for f in cat_findings:
            verdicts[f.get("verdict", "UNKNOWN")] += 1
            severities[f.get("severity", "info")] += 1
        out[code] = {
            "code": cat["code"],
            "name": cat["name"],
            "rank": cat["rank"],
            "baseline_severity": cat["baseline_severity"],
            "findings_count": len(cat_findings),
            "verdicts": dict(verdicts),
            "severities": dict(severities),
            "vulnerable_count": verdicts.get("VULNERABLE", 0),
            "suspicious_count": verdicts.get("SUSPICIOUS", 0),
            "covered": len(cat_findings) > 0,
        }
    return out, unmapped


def gaps(coverage_map, complete_scan=False):
    out = []
    for code, cat in CATEGORIES.items():
        info = coverage_map.get(code) or {}
        if info.get("findings_count", 0) == 0:
            out.append({
                "code": cat["code"],
                "name": cat["name"],
                "rank": cat["rank"],
                "baseline_severity": cat["baseline_severity"],
                "recommendation": _recommendation_for(code),
            })
    return out


def _recommendation_for(code):
    rec = {
        "A01": "Add access-control tests: IDOR, forced browsing, JWT tampering, "
               "SSRF, CORS reflection. Run `jwt`, `graphql`, `ssrf-cloud`, "
               "`bizlogic` commands.",
        "A02": "Add misconfiguration tests: security headers, debug interfaces, "
               "exposed admin panels, default credentials, cloud storage. Run "
               "`scan-all --category single`.",
        "A03": "Run `sca` against the project or target dependency files. "
               "Generate SBOM with `sca --sbom cyclonedx`.",
        "A04": "Add cryptography tests: TLS version, cipher strength, JWT "
               "algorithm, cookie Secure flag, HSTS. Run `jwt` (weak-secret "
               "and algorithm-confusion) and `profile` with TLS checks.",
        "A05": "Add injection tests: XSS (reflected/DOM/stored), SQLi, SSTI, "
               "XXE, prompt injection. Run `domxss`, `xss`, `llm` commands.",
        "A06": "Add design-flaw tests: race conditions, workflow bypass, "
               "business-logic abuse. Run `race`, `bizlogic`, `workflow`.",
        "A07": "Add authentication tests: rate-limit on login, user "
               "enumeration, JWT validation, session handling. Run `jwt` and "
               "`scan rate-limit-absent`.",
        "A08": "Add integrity tests: insecure deserialization, unsigned "
               "updates, mass assignment. Run `openapi` and `bizlogic "
               "--mass-endpoint`.",
        "A09": "No direct scanner coverage. Verify audit logging in source. "
               "Consider adding a log-injection probe.",
        "A10": "Add exceptional-condition tests: error message disclosure, "
               "failing open, unhandled exceptions. Run `scan "
               "api-error-handling` and `scan api-info-disclosure`.",
    }
    return rec.get(code, "No specific recommendation available.")


def build_compliance_report(findings, patterns_run=None, complete_scan=False,
                            engine_cfg=None):
    cov, unmapped = coverage(findings)
    gap_list = gaps(cov, complete_scan=complete_scan)
    vulnerable_total = sum(info["vulnerable_count"] for info in cov.values())
    suspicious_total = sum(info["suspicious_count"] for info in cov.values())
    covered = sum(1 for info in cov.values() if info["covered"])

    severity_breakdown = defaultdict(int)
    for f in findings:
        severity_breakdown[f.get("severity", "info")] += 1

    return {
        "categories": cov,
        "unmapped_findings": unmapped,
        "gaps": gap_list,
        "summary": {
            "total_findings": len(findings),
            "vulnerable_total": vulnerable_total,
            "suspicious_total": suspicious_total,
            "categories_covered": covered,
            "categories_total": len(CATEGORIES),
            "coverage_pct": round(100.0 * covered / len(CATEGORIES), 1),
            "severity_breakdown": dict(severity_breakdown),
            "patterns_run": patterns_run or [],
            "unmapped_count": len(unmapped),
        },
    }


def render_markdown(report, target):
    lines = []
    lines.append(f"# OWASP Top 10:2025 Compliance Report")
    lines.append("")
    lines.append(f"**Target:** {target}")
    lines.append("")
    s = report.get("summary") or {}
    lines.append(f"**Total findings:** {s.get('total_findings', 0)}")
    lines.append(f"**Vulnerable:** {s.get('vulnerable_total', 0)}")
    lines.append(f"**Suspicious:** {s.get('suspicious_total', 0)}")
    lines.append(f"**Categories covered:** "
                 f"{s.get('categories_covered', 0)}/{s.get('categories_total', 10)} "
                 f"({s.get('coverage_pct', 0)}%)")
    lines.append("")
    lines.append("## Coverage by Category")
    lines.append("")
    lines.append("| Rank | Code | Category | Findings | Vuln | Susp | Status |")
    lines.append("|------|------|----------|----------|------|------|--------|")
    cats = report.get("categories") or {}
    for code in sorted(cats.keys(),
                       key=lambda k: cats[k].get("rank", 99)):
        info = cats[code]
        status = "covered" if info["covered"] else "**GAP**"
        lines.append(
            f"| {info['rank']} | {info['code']} | {info['name']} | "
            f"{info['findings_count']} | {info['vulnerable_count']} | "
            f"{info['suspicious_count']} | {status} |"
        )
    lines.append("")
    gap_list = report.get("gaps") or []
    if gap_list:
        lines.append("## Gaps")
        lines.append("")
        for g in gap_list:
            lines.append(f"### {g['code']} — {g['name']} "
                         f"(rank {g['rank']}, floor {g['baseline_severity']})")
            lines.append("")
            lines.append(f"- No findings mapped to this category.")
            lines.append(f"- Recommendation: {g['recommendation']}")
            lines.append("")
    unmapped = report.get("unmapped_findings") or []
    if unmapped:
        lines.append("## Unmapped Findings")
        lines.append("")
        for u in unmapped[:20]:
            lines.append(f"- `{u['pattern_id']}` — {u['reason']}")
        lines.append("")
    return "\n".join(lines)


def render_html(report, target):
    from datetime import datetime, timezone
    s = report.get("summary") or {}
    cats = report.get("categories") or {}
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    rows = []
    for code in sorted(cats.keys(), key=lambda k: cats[k].get("rank", 99)):
        info = cats[code]
        status_cls = "covered" if info["covered"] else "gap"
        status = "Covered" if info["covered"] else "GAP"
        rows.append(
            f"<tr class='{status_cls}'>"
            f"<td>{info['rank']}</td>"
            f"<td><code>{info['code']}</code></td>"
            f"<td>{info['name']}</td>"
            f"<td>{info['findings_count']}</td>"
            f"<td class='vuln'>{info['vulnerable_count']}</td>"
            f"<td class='susp'>{info['suspicious_count']}</td>"
            f"<td class='status'>{status}</td>"
            f"</tr>"
        )
    gap_rows = []
    for g in (report.get("gaps") or []):
        gap_rows.append(
            f"<li><strong>{g['code']} — {g['name']}</strong> "
            f"(rank {g['rank']}, floor {g['baseline_severity']}): "
            f"{g['recommendation']}</li>"
        )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>OWASP Top 10:2025 Compliance — {target}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
background:#0d1117;color:#c9d1d9;margin:0;padding:40px 20px}}
.container{{max-width:1100px;margin:0 auto}}
h1{{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:12px}}
h2{{color:#79c0ff;margin-top:32px}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
gap:14px;margin:24px 0}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
padding:16px;text-align:center}}
.card .n{{font-size:28px;font-weight:700;color:#58a6ff}}
.card .l{{color:#8b949e;font-size:11px;text-transform:uppercase;
letter-spacing:.5px;margin-top:6px}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #30363d;
font-size:14px}}
th{{background:#161b22;color:#79c0ff}}
tr.covered{{background:rgba(63,185,80,.06)}}
tr.gap{{background:rgba(248,81,73,.08)}}
td.vuln{{color:#f85149;font-weight:600}}
td.susp{{color:#d29922;font-weight:600}}
td.status{{font-weight:700;text-transform:uppercase;font-size:11px;
letter-spacing:.5px}}
tr.covered td.status{{color:#3fb950}}
tr.gap td.status{{color:#f85149}}
code{{background:#161b22;padding:2px 6px;border-radius:4px;font-size:13px}}
ul{{line-height:1.7}}
.meta{{color:#8b949e;font-size:14px;margin-bottom:24px}}
.footer{{margin-top:60px;padding-top:20px;border-top:1px solid #30363d;
color:#8b949e;font-size:12px;text-align:center}}
</style></head><body><div class="container">
<h1>OWASP Top 10:2025 Compliance</h1>
<div class="meta">
<strong>Target:</strong> {target}<br>
<strong>Generated:</strong> {ts}
</div>
<div class="summary">
<div class="card"><div class="n">{s.get('total_findings', 0)}</div>
<div class="l">Findings</div></div>
<div class="card"><div class="n">{s.get('vulnerable_total', 0)}</div>
<div class="l">Vulnerable</div></div>
<div class="card"><div class="n">{s.get('suspicious_total', 0)}</div>
<div class="l">Suspicious</div></div>
<div class="card"><div class="n">{s.get('coverage_pct', 0)}%</div>
<div class="l">Category coverage</div></div>
</div>
<h2>Coverage by Category</h2>
<table>
<thead><tr><th>Rank</th><th>Code</th><th>Category</th><th>Findings</th>
<th>Vuln</th><th>Susp</th><th>Status</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody></table>
<h2>Gaps</h2>
<ul>
{''.join(gap_rows) if gap_rows else '<li>No gaps — full coverage.</li>'}
</ul>
<div class="footer">Generated by sec-checker</div>
</div></body></html>"""



# ===========================================================================
# Phase 3 — add mappings for the newer patterns.
# ===========================================================================
_PHASE3_OWASP_INSTALLED = True

_PHASE3_PATTERN_MAP = {
    "ssti-probe": "A05",
    "xxe-probe": "A05",
    "nosql-probe": "A05",
    "crlf-injection": "A05",
    "open-redirect": "A01",
    "host-header-injection": "A02",
    "websocket-cswsh": "A01",
    "oauth-missing-state": "A07",
    "oauth-redirect-uri": "A01",
    "oauth-pkce-downgrade": "A07",
    "upload-probe": "A08",
    "http2-desync": "A02",
    "weak-password-policy": "A07",
    "lockout-probe": "A07",
    "weak-credential-enum": "A07",
    "timing-sqli": "A05",
    "timing-ssti": "A05",
    "timing-xxe": "A05",
    "second-order-xss": "A05",
}

_PHASE3_PREFIX_MAP = [
    ("ssti-", "A05"),
    ("xxe-", "A05"),
    ("nosql-", "A05"),
    ("crlf-", "A05"),
    ("open-redirect", "A01"),
    ("host-header-", "A02"),
    ("websocket-cswsh", "A01"),
    ("oauth-", "A07"),
    ("upload-", "A08"),
    ("http2-", "A02"),
    ("weak-password-", "A07"),
    ("lockout-", "A07"),
    ("weak-credential-", "A07"),
    ("timing-", "A05"),
    ("second-order-", "A05"),
]

for _k, _v in _PHASE3_PATTERN_MAP.items():
    PATTERN_MAP.setdefault(_k, _v)

for _pfx, _code in _PHASE3_PREFIX_MAP:
    if not any(p[0] == _pfx for p in PREFIX_MAP):
        PREFIX_MAP.append((_pfx, _code))
