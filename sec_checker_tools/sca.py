from claude_agent_sdk import tool
from engine import sca, sbom


@tool(
    "sca_scan",
    "Run a software composition analysis (SCA) scan against a local project directory. "
    "Parses dependency manifests (package.json, requirements.txt, composer.json, "
    "pom.xml, go.mod, Cargo.toml, Gemfile, and lockfiles), then queries OSV.dev for "
    "known vulnerabilities. Use when the user wants to audit their dependencies, "
    "check for CVEs, or scan a codebase for vulnerable packages.",
    {
        "project_path": str,
    },
)
async def tool_sca_scan(args):
    path = args["project_path"]
    try:
        result = sca.scan_dependencies(path)
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"sca_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    deps = result.get("dependencies") or []
    findings = result.get("vulnerabilities") or []
    counts = result.get("summary") or {}
    lines = [
        f"SCA scan: {path}",
        f"Dependency files: {len(result.get('files', []))}",
        f"Dependencies found: {len(deps)}",
        f"Vulnerabilities: {len(findings)}",
        f"  critical={counts.get('critical', 0)} high={counts.get('high', 0)} "
        f"medium={counts.get('medium', 0)} low={counts.get('low', 0)}",
        "",
    ]
    for f in findings[:25]:
        dep = f["dependency"]
        lines.append(
            f"[{f['severity'].upper()}] {dep['name']}@{dep.get('version', '')} "
            f"({dep['ecosystem']})  {f['vuln_id']}"
            + (f"  {f['cve']}" if f.get("cve") else "")
        )
        if f.get("summary"):
            lines.append(f"    {f['summary'][:200]}")
    if len(findings) > 25:
        lines.append(f"  ... and {len(findings) - 25} more")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {
            "dependencies": deps,
            "vulnerabilities": findings,
            "summary": counts,
        },
    }


@tool(
    "sbom_generate",
    "Generate a Software Bill of Materials (SBOM) from a local project directory. "
    "Emits CycloneDX 1.6 or SPDX 2.3 JSON. Use when the user needs an SBOM for "
    "compliance, supply-chain attestation, or downstream vulnerability ingestion.",
    {
        "project_path": str,
        "format": str,
    },
)
async def tool_sbom_generate(args):
    path = args["project_path"]
    fmt = (args.get("format") or "cyclonedx").lower()
    try:
        if fmt == "spdx":
            out = sbom.save_spdx(path)
        else:
            out = sbom.save_cyclonedx(path)
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"sbom_generate failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    return {
        "content": [{"type": "text", "text": f"SBOM written to: {out}"}],
        "structuredContent": {"output_path": out, "format": fmt},
    }
