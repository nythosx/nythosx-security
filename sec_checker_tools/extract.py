from claude_agent_sdk import tool

from engine.data_extractor import extract_with_pagination


@tool(
    "data_extract_paginated",
    "Dump every page of a paginated API endpoint and return the collected "
    "records (masked). Follows Link: rel=next headers and common "
    "page/offset query parameters until the dataset is exhausted or "
    "max_pages is reached. Use when you need the complete dataset from a "
    "listing endpoint, not just the first page.",
    {
        "url": str,
        "token": (str, True),
        "max_pages": (int, True),
        "max_rows": (int, True),
    },
)
async def tool_extract_paginated(args):
    url = args.get("url")
    if not url:
        return {"content": [{"type": "text", "text": "url is required"}],
                "isError": True}
    token = args.get("token") or None
    max_pages = int(args.get("max_pages") or 50)
    max_rows = int(args.get("max_rows") or 100)
    try:
        result = extract_with_pagination(url, token=token, max_pages=max_pages)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"extract failed: {type(e).__name__}: {e}"}],
                "isError": True}
    rows = result.get("rows") or []
    if not rows:
        return {"content": [{"type": "text",
                             "text": f"no rows recovered across "
                                     f"{result.get('pages_fetched', 0)} page(s)"}],
                "structuredContent": {"url": url, "rows": [],
                                       "pages": result.get("pages_fetched", 0)}}
    from engine.util import mask_row
    masked = [mask_row(r) for r in rows[:max_rows] if isinstance(r, dict)]
    header = (f"{len(rows)} row(s) recovered across "
              f"{result.get('pages_fetched', 0)} page(s) "
              f"({'authenticated' if token else 'unauthenticated'})")
    lines = [header, ""]
    for r in masked[:20]:
        lines.append("  " + str(r)[:240])
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": {"url": url, "total_rows": len(rows),
                                   "extracted": len(masked),
                                   "pages": result.get("pages_fetched", 0),
                                   "auth_used": "authenticated" if token else "unauthenticated",
                                   "rows": masked}}
