from claude_agent_sdk import tool
from engine import chain_engine
from engine.chain_registry import get_all_chains
from engine.config import load_engine
from engine.roe_guard import ROEGuard


@tool(
    "chain_scan",
    "Run an adaptive attack chain against a target. First performs recon to "
    "fingerprint the target, discover the API base, extract JS bundles, and "
    "probe common endpoints. Then selects attack chains based on discovered "
    "facts (JWT, GraphQL, SSRF, business logic, race, DOM XSS, LLM, OpenAPI, "
    "supply chain). Each chain runs its steps sequentially with fallbacks: "
    "PASS/UNKNOWN continue to the next technique, VULNERABLE stops the chain "
    "and records a finding with concrete evidence. Context flows forward "
    "between steps (for example, a cracked JWT secret becomes available to "
    "subsequent steps). Use when you want deep, targeted, adaptive testing "
    "rather than broad parallel scans.",
    {
        "target": str,
        "budget_sec": (int, True),
        "verbose": (bool, True),
        "chains": (str, True),
        "sca_path": (str, True),
    },
)
async def tool_chain_scan(args):
    target = args.get("target")
    if not target:
        return {
            "content": [{"type": "text",
                         "text": "chain_scan: 'target' is required"}],
            "isError": True,
        }

    budget = int(args.get("budget_sec") or 900)
    verbose = bool(args.get("verbose", False))
    sca_path = args.get("sca_path") or None
    chain_filter_raw = args.get("chains") or ""
    chain_filter = ([c.strip() for c in chain_filter_raw.split(",")
                     if c.strip()] if chain_filter_raw else [])

    try:
        guard = ROEGuard(engine_cfg=load_engine())
        orch = chain_engine.ChainOrchestrator(
            target, roe_guard=guard, max_budget_sec=budget, verbose=verbose)
    except RuntimeError as e:
        return {
            "content": [{"type": "text", "text": f"chain_scan: {e}"}],
            "isError": True,
        }

    if sca_path:
        orch.add_fact("sca_requested", True, source="mcp")
        orch.set_context("sca_path", sca_path)

    if chain_filter:
        all_chains = get_all_chains()
        filtered = [c for c in all_chains if c["id"] in chain_filter]
        if not filtered:
            return {
                "content": [{"type": "text",
                             "text": f"No chains match: {chain_filter}"}],
                "isError": True,
            }
        try:
            orch.run_recon()
        except Exception as e:
            return {
                "content": [{"type": "text",
                             "text": f"recon failed: {type(e).__name__}: {e}"}],
                "isError": True,
            }
        for chain in filtered:
            if orch._budget_exceeded():
                break
            orch.execute_chain(chain)
        report = orch._final_report()
    else:
        report = orch.run()

    lines = [
        f"Attack Chain Scan: {target}",
        f"Duration: {report.get('duration_sec', 0)}s",
        f"Verdict: {report.get('verdict', 'UNKNOWN')}",
        "",
        f"Facts discovered: {len(report.get('facts') or {})}",
        f"Chains executed: {len(report.get('chain_results') or [])}",
        f"Findings: {len(report.get('findings') or [])}",
    ]
    chains_run = report.get("chain_results") or []
    if chains_run:
        lines.append("")
        lines.append("Chain summary:")
        for c in chains_run:
            lines.append(
                f"  [{c.get('verdict', 'UNKNOWN')}] "
                f"{c.get('id', '?')}: {(c.get('reason') or '')[:100]}")

    findings = report.get("findings") or []
    if findings:
        lines.append("")
        lines.append("Findings:")
        for f in findings[:10]:
            lines.append(
                f"  [{f.get('chain', '?')}/{f.get('step', '?')}] "
                f"{(f.get('reason') or '')[:140]}")
        if len(findings) > 10:
            lines.append(f"  ... and {len(findings) - 10} more")

    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": report,
    }
