from claude_agent_sdk import tool

from engine import cve_lookup


@tool(
    "cve_correlation",
    "Look up known CVEs for a detected product/version against NVD. "
    "Use after fingerprinting identifies a server or framework version.",
    {"product": str, "version": str},
)
async def tool_cve_correlation(args):
    product = args.get("product") or ""
    version = args.get("version") or ""
    hits = cve_lookup.lookup(product, version)
    if not hits:
        return {"content": [{"type": "text",
                             "text": f"No CVEs found for {product} {version}"}],
                "structuredContent": {"cves": []}}
    summary = cve_lookup.summarize(hits)
    lines = [
        f"{summary['total']} CVE(s) for {product} {version}",
        f"critical={summary['critical']} high={summary['high']} "
        f"medium={summary['medium']} low={summary['low']}",
        "",
    ]
    for h in hits[:15]:
        lines.append(f"[{h['severity']}] {h['id']}: {h['summary'][:140]}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {"cves": hits, "summary": summary},
    }
