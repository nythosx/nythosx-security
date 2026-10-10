from claude_agent_sdk import tool
from engine import owasp_2025
from engine import ledger
from engine.cli import _resolve_report_target


@tool(
    "owasp_compliance",
    "Generate an OWASP Top 10:2025 compliance report for a scanned target. "
    "Maps every finding to one of the ten 2025 categories (A01 Broken Access "
    "Control, A02 Security Misconfiguration, A03 Software Supply Chain "
    "Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure "
    "Design, A07 Authentication Failures, A08 Software or Data Integrity "
    "Failures, A09 Security Logging & Alerting Failures, A10 Mishandling of "
    "Exceptional Conditions). Shows coverage per category, highlights gaps, "
    "and lists recommendations for uncovered categories. Use when the user "
    "needs compliance reporting, gap analysis, or an OWASP 2025 breakdown of "
    "scan results.",
    {
        "target": str,
        "format": str,
    },
)
async def tool_owasp_compliance(args):
    target = _resolve_report_target(args["target"])
    fmt = (args.get("format") or "md").lower()
    rows = ledger.findings_for_target(target)
    keys = ["id", "timestamp", "pattern_id", "category", "verdict",
            "severity", "reason", "wstg_id", "cwe_id", "evidence_path",
            "duration_ms"]
    findings = [dict(zip(keys, r)) for r in rows]
    report = owasp_2025.build_compliance_report(findings)
    if fmt == "json":
        import json as _json
        text = _json.dumps(report, indent=2, default=str)
    else:
        text = owasp_2025.render_markdown(report, target)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": report,
    }


@tool(
    "owasp_map_pattern",
    "Map a SEC-CHECKER pattern ID to its OWASP Top 10:2025 category. Returns "
    "category code, name, rank, baseline severity, and related CWE IDs. Use "
    "when you need to explain what OWASP 2025 risk a specific pattern covers.",
    {"pattern_id": str},
)
async def tool_owasp_map_pattern(args):
    pid = args["pattern_id"]
    code = owasp_2025.map_pattern(pid)
    if not code:
        return {"content": [{"type": "text",
                             "text": f"No OWASP 2025 mapping for '{pid}'"}],
                "isError": True}
    cat = owasp_2025.CATEGORIES[code]
    lines = [
        f"Pattern: {pid}",
        f"OWASP 2025: {cat['code']} — {cat['name']} (rank {cat['rank']})",
        f"Baseline severity: {cat['baseline_severity']}",
        f"Related CWEs: {', '.join(cat['cwe_ids'][:10])}",
        "",
        cat['description'],
    ]
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {"category": cat, "pattern_id": pid},
    }
