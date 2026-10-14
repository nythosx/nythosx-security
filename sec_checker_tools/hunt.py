from claude_agent_sdk import tool

from engine import hunt as _hunt_mod


@tool(
    "hunt",
    "One-command hunter. Given a domain or URL, runs the full playbook: "
    "Certificate Transparency subdomain enumeration, live subdomain resolution, "
    "subdomain takeover scan, framework surface probes (Laravel/Spring/"
    "WordPress/Rails/Tomcat), CVE correlation on detected versions, differential "
    "auth, 403 bypass, cache deception, HPP, deserialization, GraphQL schema "
    "walk, source map mining, and cloud storage enumeration. Returns findings "
    "sorted by severity. Use when the user asks to 'scan', 'hunt', or 'test' "
    "a domain and wants a comprehensive result.",
    {"target": str, "budget_sec": int, "max_findings": int},
)
async def tool_hunt(args):
    try:
        report = _hunt_mod.hunt(
            args["target"],
            budget_sec=int(args.get("budget_sec") or 600),
            max_findings=int(args.get("max_findings") or 25),
            verbose=False,
        )
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"hunt failed: {type(e).__name__}: {e}"}],
                "isError": True}
    lines = [
        f"Hunt: {report['target']}",
        f"Duration: {report['duration_sec']}s",
        f"Verdict: {report['verdict']}",
        f"Total findings: {report['total_findings']}",
        "",
    ]
    for f in report["findings"]:
        lines.append(f"[{f['severity'].upper()}] {f['tool']} / {f['step']}")
        lines.append(f"  {(f.get('reason') or '')[:200]}")
    if not report["findings"]:
        lines.append("No vulnerable or suspicious findings.")
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": {
                "target": report["target"],
                "verdict": report["verdict"],
                "total_findings": report["total_findings"],
                "findings": report["findings"],
            }}
