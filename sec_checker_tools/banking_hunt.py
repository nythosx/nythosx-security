from claude_agent_sdk import tool

from engine import hunt as _hunt_mod


@tool(
    "banking_hunt",
    "Run the banking engagement playbook against a target URL. Performs "
    "recon (framework fingerprint, API discovery, JS bundle analysis, "
    "banking-specific path probing), then executes the banking chains: "
    "bola-chain (cross-user authorization), unauth-exposure-chain "
    "(unauthenticated data leaks), data-extraction-chain (authenticated "
    "row extraction), rate-limit-bypass-chain (forwarded-IP bypass), plus "
    "whatever the standard chains detect. Returns findings sorted by "
    "severity and the masked data rows recovered from any endpoint. Use "
    "when the user asks to scan a banking or fintech target and wants "
    "concrete extracted rows, not just status codes.",
    {
        "target": str,
        "budget_sec": (int, True),
        "max_findings": (int, True),
        "allow_destructive": (bool, True),
    },
)
async def tool_banking_hunt(args):
    target = args.get("target")
    if not target:
        return {
            "content": [{"type": "text",
                         "text": "banking_hunt: 'target' is required"}],
            "isError": True,
        }
    budget = int(args.get("budget_sec") or 900)
    max_findings = int(args.get("max_findings") or 25)
    allow_destructive = bool(args.get("allow_destructive", False))
    try:
        report = _hunt_mod.hunt(
            target,
            budget_sec=budget,
            max_findings=max_findings,
            allow_destructive=allow_destructive,
            banking=True,
            verbose=False,
            include_standalone=False,
        )
    except RuntimeError as e:
        return {
            "content": [{"type": "text", "text": f"banking_hunt: {e}"}],
            "isError": True,
        }
    except Exception as e:
        return {
            "content": [{"type": "text",
                         "text": f"banking_hunt failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    lines = [
        f"Banking hunt: {report['target']}",
        f"Duration: {report['duration_sec']}s",
        f"Verdict: {report['verdict']}",
        f"Total findings: {report['total_findings']}",
        "",
    ]
    for f in report["findings"]:
        lines.append(f"[{f['severity'].upper()}] {f['tool']} / {f['step']}")
        lines.append(f"  {(f.get('reason') or '')[:200]}")
        for dr in (f.get("evidence") or {}).get("data_rows") or []:
            lines.append(f"  rows from {dr.get('endpoint')} "
                         f"({dr.get('auth_used')}): {dr.get('extracted')}")
    if not report["findings"]:
        lines.append("No vulnerable or suspicious findings.")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {
            "target": report["target"],
            "verdict": report["verdict"],
            "total_findings": report["total_findings"],
            "findings": report["findings"],
        },
    }
