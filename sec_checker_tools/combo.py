from claude_agent_sdk import tool
from engine import combo


@tool(
    "combo_explore",
    "Run a pairwise/cartesian combination explorer across methods and paths. "
    "Identifies outlier HTTP statuses that suggest access-control inconsistencies. "
    "Use when testing many method x path combinations for authorization gaps.",
    {
        "base_url": str,
        "paths": str,
        "methods": str,
        "strategy": str,
    },
)
async def tool_combo_explore(args):
    base = args["base_url"]
    paths = [p for p in (args.get("paths") or "/").split(",") if p]
    methods = [m.upper() for m in (args.get("methods") or "GET").split(",") if m]
    strategy = args.get("strategy") or "pairwise"
    try:
        out = combo.explore(base, {"method": methods, "path": paths},
                            strategy=strategy)
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"combo_explore failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    r = out["analysis"]
    lines = [
        f"Combination explorer: {base}  ({strategy})",
        f"Combos run: {out['combos_run']}",
        f"Verdict: {r['verdict']}",
        f"Reason: {r.get('reason', '')}",
    ]
    for o in (r.get("evidence", {}) or {}).get("outliers", [])[:10]:
        lines.append(f"  outlier: {o['status']}  {o['combo']}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {"verdict": r["verdict"], "outliers": (r.get("evidence") or {}).get("outliers", [])},
    }
