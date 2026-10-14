from __future__ import annotations

import json
import re
from pathlib import Path

from .chain_engine import register_tool


_POISON_PATTERNS = [
    (r"ignore (?:all )?previous (?:instructions|prompts?)", "high"),
    (r"ignore (?:the )?above", "high"),
    (r"disregard (?:all )?(?:previous|prior)", "high"),
    (r"system\s*prompt", "medium"),
    (r"you are now", "high"),
    (r"new instructions", "high"),
    (r"override", "medium"),
    (r"<important>", "medium"),
    (r"do not (?:tell|mention|reveal)", "high"),
    (r"read ~?/\.ssh", "critical"),
    (r"read ~?/\.aws", "critical"),
    (r"exfil", "high"),
]

_CRED_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"ASIA[0-9A-Z]{16}", "aws_temp_key"),
    (r"sk-[A-Za-z0-9_\-]{20,}", "openai_key"),
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "anthropic_key"),
    (r"ghp_[A-Za-z0-9]{36}", "github_pat"),
    (r"xox[baprs]-[0-9A-Za-z\-]+", "slack_token"),
    (r"AIza[0-9A-Za-z\-_]{35}", "google_api_key"),
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "jwt"),
    (r"-----BEGIN [A-Z]+ PRIVATE KEY-----", "private_key"),
]


def _scan_config(path):
    p = Path(path)
    if not p.exists():
        return {"error": f"config not found: {path}"}
    try:
        text = p.read_text(encoding="utf-8")
    except Exception as e:
        return {"error": f"read error: {type(e).__name__}: {e}"}
    try:
        data = json.loads(text)
    except Exception:
        data = None
    return {"raw": text, "parsed": data}


def _iter_tool_descriptions(cfg):
    if not isinstance(cfg, dict):
        return
    servers = cfg.get("mcpServers") or {}
    if not isinstance(servers, dict):
        return
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        desc = spec.get("description") or ""
        if desc:
            yield name, "server:" + name, desc
        tools = spec.get("tools") or []
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict):
                    td = tool.get("description") or ""
                    tn = tool.get("name") or "?"
                    if td:
                        yield name, "tool:" + tn, td


def _tool_mcp_security(orch, args):
    config_path = args.get("config_path") or ".mcp.json"
    check = (args.get("check") or "poisoning").lower()

    cfg = _scan_config(config_path)
    if cfg.get("error"):
        return {"verdict": "UNKNOWN", "reason": cfg["error"],
                "evidence": {"config_path": config_path}}

    raw = cfg.get("raw") or ""

    if check == "credentials":
        hits = []
        for pat, label in _CRED_PATTERNS:
            try:
                for m in re.finditer(pat, raw):
                    hits.append({"type": label,
                                 "match": m.group(0)[:40]})
            except re.error:
                continue
        if hits:
            return {
                "verdict": "VULNERABLE",
                "reason": f"{len(hits)} credential(s) hardcoded in {config_path}",
                "evidence": {"config_path": config_path, "credentials": hits},
            }
        return {"verdict": "PASS",
                "reason": f"no hardcoded credentials found in {config_path}",
                "evidence": {"config_path": config_path}}

    parsed = cfg.get("parsed")
    hits = []
    for server, where, desc in _iter_tool_descriptions(parsed or {}):
        for pat, sev in _POISON_PATTERNS:
            try:
                m = re.search(pat, desc, re.IGNORECASE)
            except re.error:
                continue
            if m:
                hits.append({"server": server, "where": where,
                             "severity": sev, "pattern": pat,
                             "match": m.group(0)[:80],
                             "context": desc[:200]})
                break

    if hits:
        critical = [h for h in hits if h["severity"] in ("critical", "high")]
        return {
            "verdict": "VULNERABLE" if critical else "SUSPICIOUS",
            "reason": f"{len(hits)} tool-poisoning pattern(s) in {config_path}",
            "evidence": {"config_path": config_path, "hits": hits},
        }
    return {"verdict": "PASS",
            "reason": f"no poisoning patterns in {config_path}",
            "evidence": {"config_path": config_path}}


register_tool("mcp_security", _tool_mcp_security)
