import json
from claude_agent_sdk import tool
from engine import llm_security
from engine.config import load_engine
from engine.roe_guard import ROEGuard


@tool(
    "llm_scan",
    "Run an OWASP LLM Top 10 security scan against an LLM API endpoint. "
    "Detects prompt injection (LLM01), sensitive information disclosure (LLM02), "
    "improper output handling (LLM05), excessive agency (LLM06), and system prompt "
    "leakage (LLM07). Use when the target is a chat/completion API, an AI agent, "
    "or any endpoint that accepts natural-language input.",
    {
        "target_url": str,
        "model": str,
        "api_key": str,
    },
)
async def tool_llm_scan(args):
    target = args["target_url"]
    model = args.get("model") or "gpt-3.5-turbo"
    headers = {"Content-Type": "application/json"}
    key = args.get("api_key") or ""
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        results = llm_security.scan(target, model=model, headers=headers, roe_guard=guard)
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"llm_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    vuln = [r for r in results if r["verdict"] == "VULNERABLE"]
    passed = [r for r in results if r["verdict"] == "PASS"]
    unknown = [r for r in results if r["verdict"] == "UNKNOWN"]
    lines = [
        f"LLM Security Scan: {target}",
        f"Model: {model}",
        f"Vulnerable: {len(vuln)} | Pass: {len(passed)} | Unknown: {len(unknown)}",
        "",
    ]
    for r in results:
        lines.append(
            f"[{r['verdict']}] {r['category']} ({r.get('owasp', '')}) "
            f"[{r['severity']}]: {r['reason']}"
        )
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {"results": results},
    }
