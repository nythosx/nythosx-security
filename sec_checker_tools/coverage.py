from claude_agent_sdk import tool

from engine import ledger
from engine import coverage as coverage_mod


@tool(
    "sec_coverage",
    "Build an OWASP Top 10:2025 and attack-surface coverage report for a "
    "target based on findings recorded in the ledger.",
    {"target": str},
)
async def tool_sec_coverage(args):
    target = args["target"]
    rows = ledger.findings_for_target(target)
    findings = []
    for r in rows:
        findings.append({"pattern_id": r[2], "verdict": r[4]})
    report = coverage_mod.build_coverage_report(
        target=target, findings=findings,
        executed_caps=[f["pattern_id"] for f in findings],
    )
    lines = [f"Coverage report for {target}",
             f"Executed: {report['executed_count']} / {report['total_count']}",
             ""]
    for code in sorted(report["owasp"].keys()):
        info = report["owasp"][code]
        if info["total"] == 0:
            continue
        lines.append(f"  {code}: {info['coverage_pct']:5.1f}%  "
                     f"({info['covered']}/{info['total']})")
    if report["untested_categories"]:
        lines.append("")
        lines.append(f"Untested categories: {', '.join(report['untested_categories'])}")
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": report}
