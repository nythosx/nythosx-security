from claude_agent_sdk import tool

from engine import upload_probe
from engine.config import load_engine
from engine.roe_guard import ROEGuard
from engine import registry


try:
    registry.register(upload_probe.CAPABILITY)
except Exception:
    pass


@tool(
    "upload_scan",
    "File upload restriction testing: extension bypass, magic bytes, path "
    "traversal, SVG XSS. Destructive — writes files. Disabled unless "
    "upload.opt_in is true in engine.yaml.",
    {"upload_url": str, "field_name": str},
)
async def tool_upload_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = upload_probe.scan(args["upload_url"],
                              field_name=args.get("field_name") or "file",
                              roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"upload_scan error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
