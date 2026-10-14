from claude_agent_sdk import tool

from engine.config import load_engine
from engine.frameworks import scan_all
from engine.roe_guard import ROEGuard


@tool(
    "framework_probe",
    "Probe known-vulnerable framework surfaces safely (read-only). "
    "Covers Laravel Ignition CVE-2021-3129 surface, Laravel Telescope/debugbar/logs, "
    "Spring Boot Actuator (env, heapdump, gateway routes, loggers), WordPress user "
    "enumeration + xmlrpc, Rails dev routes + conductor, Tomcat manager/examples, "
    "and generic server misconfigs (.git, .env, nginx_status, Dockerfile). "
    "Never exploits; only detects that the surface is present.",
    {"base_url": str},
)
async def tool_framework_probe(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = scan_all(args["base_url"], roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"framework_probe error: {type(e).__name__}: {e}"}],
                "isError": True}
    findings = r.get("findings") or []
    lines = [
        f"Framework surface probe: {args['base_url']}",
        f"Modules run: {', '.join(r.get('modules_run') or [])}",
        f"Findings: {len(findings)}",
        "",
    ]
    for f in findings[:20]:
        cve = f" ({f['cve']})" if f.get("cve") else ""
        lines.append(f"[{f.get('severity', '?').upper()}] {f['probe']}{cve}")
        lines.append(f"    {f.get('reason', '')}")
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": r}
