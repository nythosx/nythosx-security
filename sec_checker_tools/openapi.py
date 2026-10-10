from claude_agent_sdk import tool
from engine import openapi_scanner
from engine.roe_guard import ROEGuard
from engine.config import load_engine


@tool(
    "openapi_scan",
    "Discover an OpenAPI/Swagger specification and drive schema-based fuzzing. "
    "Probes 20+ spec paths (/openapi.json, /swagger.json, /v3/api-docs, etc.) "
    "plus Swagger UI pages (extracting embedded spec URLs). Parses OpenAPI 2.0 "
    "and 3.x. Extracts endpoints, parameters, request bodies, auth schemes. "
    "Then fuzzes each endpoint with boundary values (MAX_INT, MIN_INT, NaN, "
    "empty, oversized) and injection payloads (SQLi, XSS, path traversal, "
    "SSTI) inferred from each parameter's schema type. Reports anomalies "
    "(5xx responses, SQL/stack-trace signatures) and produces an endpoint "
    "coverage report. Use when the target exposes an API and you want "
    "spec-driven security testing.",
    {
        "target_url": str,
        "fuzz": bool,
        "max_endpoints": int,
        "max_fuzz_per_endpoint": int,
    },
)
async def tool_openapi_scan(args):
    target = args["target_url"]
    fuzz = bool(args.get("fuzz", True))
    max_endpoints = int(args.get("max_endpoints") or 50)
    max_fuzz = int(args.get("max_fuzz_per_endpoint") or 40)
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        out = openapi_scanner.scan(target, roe_guard=guard, fuzz=fuzz,
                                    max_endpoints=max_endpoints,
                                    max_fuzz_per_endpoint=max_fuzz)
    except Exception as e:
        return {
            "content": [{"type": "text",
                         "text": f"openapi_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    lines = [f"OpenAPI scan: {target}"]
    if not out.get("spec"):
        lines.append(f"No spec: {out.get('reason', '')}")
        return {"content": [{"type": "text", "text": "\n".join(lines)}]}
    spec = out["spec"]
    lines.append(f"Spec: {spec['url']}  ({spec['format']} {spec['version']})")
    cov = out.get("coverage") or {}
    lines.append(f"Endpoints: {cov.get('total_endpoints', 0)}")
    lines.append(f"Auth schemes: {len(out.get('auth_schemes') or [])}")
    lines.append(f"Anomalies: {len(out.get('anomalies') or [])}")
    lines.append(f"Verdict: {out.get('verdict')}")
    for a in (out.get("anomalies") or [])[:10]:
        lines.append(f"  [{a.get('type')}] {a.get('case')}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": out,
    }
