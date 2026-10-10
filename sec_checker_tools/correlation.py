from claude_agent_sdk import tool

from engine import ledger
from engine.correlator import resolve_chains, render


@tool(
    "sec_chains",
    "Resolve attack chains across findings for a target. Returns chains with "
    "verdict (CONFIRMED/LIKELY/THEORETICAL/INCOMPLETE) and step-by-step narrative.",
    {"target": str},
)
async def tool_sec_chains(args):
    target = args["target"]
    rows = ledger.findings_for_target(target)
    findings = []
    for r in rows:
        findings.append({
            "pattern_id": r[2],
            "verdict": r[4],
            "severity": r[5],
        })
    chains = resolve_chains(findings)
    active = [c for c in chains if c.verdict in ("CONFIRMED", "LIKELY",
                                                   "THEORETICAL")]
    lines = [f"Attack chains for {target}: {len(active)}/{len(chains)} active", ""]
    for c in active[:15]:
        lines.append(f"[{c.verdict}] {c.id}: {c.name} "
                     f"(confidence={c.confidence:.2f})")
        if c.missing:
            lines.append(f"    missing: {', '.join(c.missing)}")
    if active:
        lines.append("")
        lines.append("Top chain narrative:")
        lines.append(render(active[0]))
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": {"chains": [c.to_dict() for c in chains]}}
