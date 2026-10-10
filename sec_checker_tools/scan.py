import json
from claude_agent_sdk import tool
from engine import loader, executor, oracle
from engine.config import load_engine


def _run(pattern_id, target, headers=None, cookies=None):
    pattern = loader.load_pattern(pattern_id)
    if not pattern:
        return None
    inputs = {"target_url": target}
    for k, v in (pattern.get("inputs") or {}).items():
        if v is None:
            v = {}
        if k == "target_url":
            continue
        if v.get("default") is not None:
            inputs[k] = v["default"]
        else:
            inputs[k] = ""
    cfg = load_engine()
    ctx = executor.execute_pattern(
        pattern, inputs, target,
        default_headers=headers or {},
        engine_config=cfg,
        cookies=cookies or {},
    )
    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    best = None
    for o in pattern.get("oracles", []):
        r = oracle.evaluate(o, ctx)
        if best is None or rank.get(r["verdict"], 0) > rank.get(best["verdict"], 0):
            best = r
    if best is None:
        best = {"verdict": "UNKNOWN", "reason": "no oracles", "evidence": {}}
    return {"pattern": pattern, "context": ctx, "result": best}


@tool(
    "sec_scan",
    "Run a single SEC-CHECKER security pattern against a target URL. "
    "Choose a pattern_id from the SEC-CHECKER pattern library (e.g. "
    "'security-headers-missing', 'cors-wildcard', 'llm-prompt-injection', "
    "'env-file-exposure'). Use for targeted checks when the specific weakness "
    "is already known or suspected.",
    {
        "pattern_id": str,
        "target_url": str,
        "auth_header": str,
    },
)
async def tool_sec_scan(args):
    pid = args["pattern_id"]
    target = args["target_url"]
    headers = {}
    auth = args.get("auth_header") or ""
    if auth:
        if auth.startswith("bearer:"):
            headers["Authorization"] = f"Bearer {auth[7:]}"
        elif auth.startswith("apikey:"):
            headers["X-API-Key"] = auth[7:]
        elif ":" in auth:
            headers["Authorization"] = f"Basic {auth}"
    out = _run(pid, target, headers=headers)
    if out is None:
        return {
            "content": [{"type": "text", "text": f"Pattern not found: {pid}"}],
            "isError": True,
        }
    r = out["result"]
    text = (
        f"Pattern: {pid}\n"
        f"Target: {target}\n"
        f"Verdict: {r['verdict']}\n"
        f"Reason: {r.get('reason', '')}\n"
        f"Evidence: {json.dumps(r.get('evidence', {}), default=str)[:800]}"
    )
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"verdict": r["verdict"], "evidence": r.get("evidence", {})},
    }


@tool(
    "sec_list_patterns",
    "List every SEC-CHECKER security pattern available to scan, grouped by category. "
    "Use before sec_scan when the exact pattern_id is unknown.",
    {},
)
async def tool_sec_list_patterns(args):
    patterns = loader.list_patterns()
    lines = [f"Available patterns ({len(patterns)}):", ""]
    by_cat = {}
    for p in patterns:
        by_cat.setdefault(p["category"], []).append(p)
    for cat in sorted(by_cat):
        lines.append(f"[{cat}]")
        for p in by_cat[cat]:
            lines.append(f"  {p['id']}  ({p['severity']})  {p['name']}")
        lines.append("")
    return {"content": [{"type": "text", "text": "\n".join(lines)}]}
