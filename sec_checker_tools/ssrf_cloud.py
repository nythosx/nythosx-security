from claude_agent_sdk import tool
from engine import ssrf_cloud
from engine.roe_guard import ROEGuard
from engine.config import load_engine


@tool(
    "ssrf_cloud_scan",
    "Probe cloud metadata endpoints (AWS IMDSv1/v2, GCP, Azure IMDS, ECS, "
    "Lambda runtime, DigitalOcean, Alibaba, Oracle Cloud, Kubernetes SA token). "
    "Detects whether a target can be pivoted into full cloud account compromise "
    "via SSRF. Also tests IP-encoding bypasses (decimal, hex, octal, mixed) and "
    "DNS rebinding (nip.io, sslip.io, xip.io). Use when the target makes "
    "server-side HTTP requests and runs on a cloud host. WARNING: this sends "
    "real probes to 169.254.169.254 and metadata.google.internal. Ensure the "
    "target is authorized and running in an isolated lab.",
    {
        "base_url": str,
        "timeout": int,
        "include_protocols": bool,
        "fuzz_param_url": str,
    },
)
async def tool_ssrf_cloud_scan(args):
    base_url = args.get("base_url") or None
    timeout = int(args.get("timeout") or 8)
    include_protocols = bool(args.get("include_protocols", False))
    fuzz_param = args.get("fuzz_param_url") or None
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        out = ssrf_cloud.scan(base_url=base_url, timeout=timeout,
                               roe_guard=guard,
                               include_protocol_smuggling=include_protocols,
                               fuzz_param_url=fuzz_param)
    except Exception as e:
        return {
            "content": [{"type": "text",
                         "text": f"ssrf_cloud_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    lines = [f"Cloud Metadata SSRF: {out.get('target', '(local)')}",
             f"Overall: {out.get('overall')}",
             f"Reason: {out.get('reason', '')}",
             ""]
    for name, r in (out.get("providers") or {}).items():
        lines.append(f"[{r.get('verdict')}] {name}: {r.get('reason', '')[:120]}")
    for name, r in (out.get("bypasses") or {}).items():
        if isinstance(r, dict):
            lines.append(f"[{r.get('verdict')}] bypass/{name}: {r.get('reason', '')[:120]}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": out,
    }
