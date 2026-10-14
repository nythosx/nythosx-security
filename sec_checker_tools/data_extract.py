from claude_agent_sdk import tool

from engine.config import load_engine
from engine.data_extractor import extract_endpoint
from engine.roe_guard import ROEGuard


@tool(
    "data_extract",
    "Extract masked data rows from a single target endpoint. Sends one "
    "HTTP request (GET by default), parses the JSON response, unwraps the "
    "common envelope keys (data / items / results / records / content / "
    "accounts / transactions / customers / users), and returns up to "
    "max_rows rows with sensitive-looking fields masked. The first "
    "character of each sensitive value is preserved; the rest is rotated. "
    "Use when you need a concrete, report-ready sample of what an endpoint "
    "returns. ROE is enforced fail-closed: an out-of-scope URL is refused "
    "before any traffic leaves the process.",
    {
        "url": str,
        "token": (str, True),
        "method": (str, True),
        "max_rows": (int, True),
    },
)
async def tool_data_extract(args):
    url = args.get("url")
    if not url:
        return {
            "content": [{"type": "text", "text": "data_extract: 'url' is required"}],
            "isError": True,
        }
    token = args.get("token") or None
    method = (args.get("method") or "GET").upper()
    max_rows = int(args.get("max_rows") or 5)
    try:
        guard = ROEGuard(engine_cfg=load_engine())
    except Exception as e:
        return {
            "content": [{"type": "text",
                         "text": f"data_extract: ROE init failed: {e}"}],
            "isError": True,
        }
    row, err, kind = extract_endpoint(
        url, token=token, method=method, roe_guard=guard,
        max_rows=max_rows,
        auth_label="authenticated" if token else "unauthenticated",
    )
    if row is None:
        return {
            "content": [{"type": "text", "text": f"{kind}: {err}"}],
            "structuredContent": {"url": url, "kind": kind, "error": err,
                                    "rows": []},
        }
    return {
        "content": [{"type": "text", "text": row.masked_json()}],
        "structuredContent": {
            "url": row.endpoint,
            "auth_used": row.auth_used,
            "total_rows": row.total_rows,
            "extracted": row.extracted,
            "rows": row.rows,
        },
    }
