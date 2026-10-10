from claude_agent_sdk import tool

from engine.brains.rule_based import RuleBasedBrain
from engine.config import load_engine
from engine.orchestrator import Orchestrator


@tool(
    "sec_orchestrate",
    "Run a full multi-pass scan via the orchestrator with the deterministic "
    "RuleBasedBrain. Profile: quick | standard | deep.",
    {"target": str, "profile": str},
)
async def tool_sec_orchestrate(args):
    target = args["target"]
    profile = args.get("profile") or "standard"
    try:
        orc = Orchestrator(brain=RuleBasedBrain(), engine_cfg=load_engine())
        state = orc.run(target, profile=profile)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"sec_orchestrate error: {type(e).__name__}: {e}"}],
                "isError": True}
    lines = [
        f"Orchestrated scan: {target} ({profile})",
        f"Iterations: {state.iterations}",
        f"Findings: {len(state.findings)}",
        f"Executed capabilities: {len(state.executed_capabilities)}",
        f"Elapsed: {state.elapsed_seconds:.1f}s",
    ]
    if state.chains:
        active = [c for c in state.chains
                  if c.verdict in ("CONFIRMED", "LIKELY")]
        lines.append(f"Active chains: {len(active)}")
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": state.to_dict()}
