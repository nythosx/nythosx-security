from claude_agent_sdk import tool

from engine import websocket_probe
from engine.config import load_engine
from engine.roe_guard import ROEGuard
from engine import registry


try:
    registry.register(websocket_probe.CAPABILITY)
except Exception:
    pass


@tool(
    "websocket_scan",
    "WebSocket security: unauthenticated handshake, Cross-Site WebSocket "
    "Hijacking (CSWSH), message reflection. Requires the websockets library.",
    {"target_url": str},
)
async def tool_websocket_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = websocket_probe.scan(args["target_url"], roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"websocket_scan error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
