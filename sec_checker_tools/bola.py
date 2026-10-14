from claude_agent_sdk import tool

from engine import bola_scanner
from engine.bola_scanner import harvest_sequential_ids
from engine.config import load_engine
from engine.roe_guard import ROEGuard


def _orch_stub(base_url, token_a, token_b):
    class _Stub:
        pass

    s = _Stub()
    s.target = base_url
    s.roe_guard = None
    s.recon = {"api_paths": [], "live_paths": []}
    s.context = {"jwt_token": token_a}
    if token_b:
        s.context["jwt_token_b"] = token_b
    s.facts = {}
    s.diagnostics = []

    def get_fact(k, default=None):
        return s.facts.get(k, default)

    def get_context(k, default=None):
        return s.context.get(k, default)

    def set_context(k, v):
        s.context[k] = v

    def add_fact(k, v, source=None, confidence=None):
        s.facts[k] = {"value": v, "source": source}

    s.get_fact = get_fact
    s.get_context = get_context
    s.set_context = set_context
    s.add_fact = add_fact
    return s




@tool(
    "bola_harvest",
    "Harvest cross-user records via Broken Object Level Authorization. Walks "
    "the sequential ID space of an endpoint template like "
    "'/api/v1/orders/{id}' using a single valid user token and collects every "
    "record the server returns. The server checks authentication but not "
    "authorization, so one user's token unlocks every other user's data. "
    "Returns masked records with their owner field, which is the evidence "
    "you need to prove BOLA.",
    {
        "base_url": str,
        "endpoint_template": str,
        "token": str,
        "max_records": (int, True),
        "timeout": (int, True),
    },
)
async def tool_bola_harvest(args):
    base_url = args.get("base_url")
    template = args.get("endpoint_template")
    token = args.get("token")
    if not base_url or not template or not token:
        return {"content": [{"type": "text",
                             "text": "base_url, endpoint_template, and token are required"}],
                "isError": True}
    max_records = int(args.get("max_records") or 100)
    timeout = int(args.get("timeout") or 10)
    try:
        harvested = harvest_sequential_ids(
            base_url, template, token, max_records=max_records,
            timeout=timeout,
        )
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"harvest failed: {type(e).__name__}: {e}"}],
                "isError": True}
    if not harvested:
        return {"content": [{"type": "text",
                             "text": f"no records harvested across ID space of {template}"}],
                "structuredContent": {"endpoint": template, "records": []}}
    owners = sorted({str(h["owner_value"]) for h in harvested
                     if h.get("owner_value") is not None})
    lines = [f"Endpoint: {template}",
             f"Records harvested: {len(harvested)}",
             f"Distinct owners: {len(owners)}"]
    from engine.util import mask_row
    for h in harvested[:20]:
        sample = h["rows"][0] if h.get("rows") else {}
        masked = mask_row(sample) if isinstance(sample, dict) else {}
        lines.append(f"  id={h['id']} owner={h.get('owner_value')} "
                     f"sample={str(masked)[:180]}")
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": {"endpoint": template,
                                   "total_records": len(harvested),
                                   "distinct_owners": len(owners),
                                   "records": [{"id": h["id"],
                                                "owner": h.get("owner_value"),
                                                "rows": h["rows"][:1]}
                                               for h in harvested[:50]]}}


@tool(
    "bola_scan",
    "Test a target for Broken Object Level Authorization (BOLA) and "
    "Broken Function Level Authorization (BFLA). Two modes: (a) when both "
    "token_a and token_b are provided, the tool probes each ID-bearing "
    "endpoint with each token and flags any endpoint where the two "
    "responses differ with 200 rows (cross-user exposure); (b) when only "
    "token_a is provided, the tool probes sequential-ID endpoints with the "
    "single session and flags any that return data (indicative of BOLA, "
    "requires a second user to confirm). Rows from any exposed endpoint "
    "are returned masked. ROE is enforced fail-closed.",
    {
        "base_url": str,
        "token_a": str,
        "token_b": (str, True),
        "endpoints": (str, True),
        "max_rows": (int, True),
        "timeout": (int, True),
    },
)
async def tool_bola_scan(args):
    base_url = args.get("base_url")
    token_a = args.get("token_a")
    if not base_url or not token_a:
        return {
            "content": [{"type": "text",
                         "text": "bola_scan: 'base_url' and 'token_a' are required"}],
            "isError": True,
        }
    token_b = args.get("token_b") or ""
    endpoints = args.get("endpoints")
    if isinstance(endpoints, str):
        endpoints = [e.strip() for e in endpoints.split(",") if e.strip()]
    max_rows = int(args.get("max_rows") or 5)
    timeout = int(args.get("timeout") or 10)
    try:
        guard = ROEGuard(engine_cfg=load_engine())
    except Exception as e:
        return {
            "content": [{"type": "text",
                         "text": f"bola_scan: ROE init failed: {e}"}],
            "isError": True,
        }
    stub = _orch_stub(base_url, token_a, token_b)
    stub.roe_guard = guard
    mcp_args = {
        "base_url": base_url,
        "token_a": token_a,
        "token_b": token_b,
        "max_rows": max_rows,
        "timeout": timeout,
    }
    if endpoints:
        mcp_args["endpoints"] = endpoints
    try:
        out = bola_scanner._tool_bola_scan(stub, mcp_args)
    except Exception as e:
        return {
            "content": [{"type": "text",
                         "text": f"bola_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    verdict = out.get("verdict", "UNKNOWN")
    reason = out.get("reason", "")
    evidence = out.get("evidence") or {}
    lines = [
        f"BOLA scan: {base_url}",
        f"Verdict: {verdict}",
        f"Reason: {reason}",
        f"Two sessions: {evidence.get('two_sessions', False)}",
    ]
    findings = evidence.get("findings") or []
    if findings:
        lines.append("")
        lines.append(f"Exposed endpoints ({len(findings)}):")
        for f in findings[:5]:
            lines.append("  " + str(f.get("url") or f.get("path")))
            for r in (f.get("b_rows_sample") or f.get("rows") or [])[:max_rows]:
                lines.append("    " + str(r)[:200])
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {
            "verdict": verdict,
            "reason": reason,
            "two_sessions": evidence.get("two_sessions", False),
            "findings": findings,
            "data_rows": out.get("data_rows") or [],
        },
    }
