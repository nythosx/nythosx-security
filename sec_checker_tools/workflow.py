from claude_agent_sdk import tool
from engine import workflow_recorder
from engine.roe_guard import ROEGuard
from engine.config import load_engine


@tool(
    "workflow_record",
    "Launch a headful browser to record a multi-step user workflow (clicks, "
    "form inputs, submissions, navigation). Saves to JSON. WARNING: this "
    "blocks on stdin waiting for the user to press Enter, so it only works "
    "in an interactive terminal — do not call from an automated agent. "
    "For non-interactive use, record once manually then call workflow_replay.",
    {
        "url": str,
        "out_file": str,
    },
)
async def tool_workflow_record(args):
    return {
        "content": [{"type": "text",
                     "text": ("workflow_record requires interactive stdin. "
                              "Run manually: python run.py workflow record <url> "
                              "--out <file>")}],
        "isError": True,
    }


@tool(
    "workflow_list_params",
    "List all modifiable parameters from a recorded workflow JSON, with a "
    "flag showing which are business-critical (price, quantity, role, etc.).",
    {"workflow_file": str},
)
async def tool_workflow_list_params(args):
    wf = workflow_recorder.load_workflow(args["workflow_file"])
    if not wf:
        return {"content": [{"type": "text", "text": "cannot load workflow"}],
                "isError": True}
    params = workflow_recorder.list_modifiable_params(wf)
    lines = [f"Parameters ({len(params)}):"]
    for p in params:
        flag = " [CRITICAL]" if p["critical"] else ""
        lines.append(f"  {p['name']} = {p.get('original')}{flag}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {"params": params},
    }


@tool(
    "workflow_replay",
    "Replay a recorded workflow with optional parameter substitutions. Runs "
    "headlessly. Use to test whether a workflow still completes when "
    "business-critical parameters are changed (e.g., price=0.01, role=admin).",
    {
        "url": str,
        "workflow_file": str,
        "substitutions_json": str,
    },
)
async def tool_workflow_replay(args):
    import json as _json
    wf = workflow_recorder.load_workflow(args["workflow_file"])
    if not wf:
        return {"content": [{"type": "text", "text": "cannot load workflow"}],
                "isError": True}
    subs = {}
    if args.get("substitutions_json"):
        try:
            subs = _json.loads(args["substitutions_json"])
        except Exception:
            pass
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        out = workflow_recorder.replay(args["url"], wf, substitutions=subs,
                                        roe_guard=guard, headless=True)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"replay failed: {type(e).__name__}: {e}"}],
                "isError": True}
    lines = [f"Replay: {args['url']}",
             f"Success: {out.get('success')}",
             f"Final URL: {out.get('final_url')}"]
    for s in (out.get("steps") or [])[:20]:
        status = "OK" if s.get("ok") else "FAIL"
        lines.append(f"  [{status}] {s.get('event')}: {s.get('selector', '')[:60]}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": out,
    }


@tool(
    "workflow_tamper",
    "Auto-tamper every business-critical parameter in a recorded workflow and "
    "replay headlessly. Replaces price with 0.01, quantity with 999999, role "
    "with admin, status with approved, etc. Reports which tampered workflows "
    "completed successfully — a strong signal for a business logic flaw.",
    {
        "url": str,
        "workflow_file": str,
    },
)
async def tool_workflow_tamper(args):
    wf = workflow_recorder.load_workflow(args["workflow_file"])
    if not wf:
        return {"content": [{"type": "text", "text": "cannot load workflow"}],
                "isError": True}
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        out = workflow_recorder.replay_with_critical_tampers(
            args["url"], wf, roe_guard=guard, headless=True)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"tamper failed: {type(e).__name__}: {e}"}],
                "isError": True}
    lines = [f"Workflow tamper: {args['url']}",
             f"Verdict: {out.get('verdict')}",
             f"Reason: {out.get('reason', '')}", ""]
    for r in out.get("results") or []:
        outcome = "completed" if r.get("success") else "failed"
        lines.append(f"  {r['param']}: {r.get('original')} → "
                     f"{r.get('tampered_to')} — {outcome}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": out,
    }
