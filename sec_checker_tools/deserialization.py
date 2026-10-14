from claude_agent_sdk import tool

from engine import deserialization
from engine.config import load_engine
from engine.roe_guard import ROEGuard


@tool(
    "deserialization_scan",
    "Detect unsafe deserialization. Sends Java/PHP/Python/.NET magic-byte "
    "payloads to cookie, header, and JSON body reflection points, then looks "
    "for parser error signatures that prove the endpoint reached a native "
    "deserializer (java.io.ObjectInputStream, unserialize, pickle, "
    "BinaryFormatter). Non-destructive; payloads are inert magic bytes.",
    {"target_url": str, "method": str},
)
async def tool_deserialization_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = deserialization.scan(args["target_url"],
                                 method=(args.get("method") or "POST").upper(),
                                 roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"deserialization error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
