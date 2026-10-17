"""Remote MCP server probe.

Connects to an MCP server over the Streamable HTTP transport (POST with
JSON-RPC), enumerates its tools, and scans each tool description for
poisoning patterns and embedded credentials. The local static scanner
in engine/mcp_security.py only covers on-disk config files; this covers
live servers.

Every POST routes through engine.http (scope gate + rate limiter).
"""
from __future__ import annotations

import json
import re

from .chain_engine import register_tool
from .config import load_engine
from .contract import Capability, ScanResult
from .roe_guard import ROEViolation
from . import http as _http


CAPABILITY = Capability(
    name="mcp_remote_probe",
    description=("Connect to a remote MCP server URL, enumerate its tools "
                 "over JSON-RPC, and scan each tool description for "
                 "poisoning patterns or embedded credentials."),
    category="recon",
    cost="medium",
    destructive=False,
    idempotent=True,
)


try:
    from .mcp_security import _POISON_PATTERNS, _CRED_PATTERNS
except Exception:
    _POISON_PATTERNS = [
        (r"ignore (?:all )?previous (?:instructions|prompts?)", "high"),
        (r"ignore (?:the )?above", "high"),
        (r"disregard (?:all )?(?:previous|prior)", "high"),
        (r"system\s*prompt", "medium"),
        (r"you are now", "high"),
        (r"read ~?/\.ssh", "critical"),
        (r"read ~?/\.aws", "critical"),
    ]
    _CRED_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
        (r"sk-[A-Za-z0-9_\-]{20,}", "openai_key"),
        (r"ghp_[A-Za-z0-9]{36}", "github_pat"),
    ]


_PROTOCOL_VERSION = "2024-11-05"
_CLIENT_INFO = {"name": "sec-checker-probe", "version": "1.0"}
_MAX_TOOLS = 200


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _post_rpc(base_url, body, headers=None, timeout=10, verify=None,
              roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    if roe_guard is not None:
        try:
            roe_guard.check_url(base_url, "POST")
        except ROEViolation as e:
            return {"blocked": True, "error": f"ROE_BLOCK: {e}"}
    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if headers:
        req_headers.update(headers)
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(base_url, json=body, headers=req_headers)
    except _http.ROEBlock as e:
        return {"blocked": True, "error": f"ROE_BLOCK: {e}"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}
    return {
        "status": r.status_code,
        "body": r.text or "",
        "headers": {k.lower(): v for k, v in r.headers.items()},
    }


def _try_parse_jsonrpc_response(body):
    if not body:
        return None
    text = body.strip()
    if text.startswith("{"):
        try:
            return json.loads(text)
        except Exception:
            pass
    for chunk in text.split("\n\n"):
        for line in chunk.split("\n"):
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload:
                    try:
                        return json.loads(payload)
                    except Exception:
                        continue
    return None


def _initialize(base_url, headers=None, timeout=10, verify=None,
                roe_guard=None):
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": _CLIENT_INFO,
        },
    }
    r = _post_rpc(base_url, body, headers, timeout, verify, roe_guard)
    if r.get("blocked"):
        return r
    if r.get("status") not in (200, 201, 202):
        return {"error": f"initialize returned HTTP {r.get('status')}",
                "raw": (r.get("body") or "")[:500]}
    parsed = _try_parse_jsonrpc_response(r.get("body") or "")
    if parsed is None:
        return {"error": "initialize response is not JSON/SSE",
                "raw": (r.get("body") or "")[:500]}
    session_id = r.get("headers", {}).get("mcp-session-id")
    server_info = (parsed.get("result") or {}).get("serverInfo") or {}
    return {"ok": True, "session_id": session_id,
            "server_info": server_info, "parsed": parsed}


def _list_tools(base_url, session_id=None, headers=None, timeout=10,
                verify=None, roe_guard=None):
    req_headers = dict(headers or {})
    if session_id:
        req_headers["Mcp-Session-Id"] = session_id
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    r = _post_rpc(base_url, body, req_headers, timeout, verify, roe_guard)
    if r.get("blocked"):
        return r
    if r.get("status") not in (200, 201, 202):
        return {"error": f"tools/list returned HTTP {r.get('status')}",
                "raw": (r.get("body") or "")[:500]}
    parsed = _try_parse_jsonrpc_response(r.get("body") or "")
    if parsed is None:
        return {"error": "tools/list response is not JSON/SSE",
                "raw": (r.get("body") or "")[:500]}
    tools = (parsed.get("result") or {}).get("tools") or []
    return {"ok": True, "tools": tools[:_MAX_TOOLS]}


def _scan_description(name, desc):
    hits = []
    for pat, severity in _POISON_PATTERNS:
        try:
            m = re.search(pat, desc or "", re.IGNORECASE)
        except re.error:
            continue
        if m:
            hits.append({"type": "poisoning", "severity": severity,
                         "pattern": pat, "match": m.group(0)[:80]})
            break
    for pat, label in _CRED_PATTERNS:
        m = re.search(pat, desc or "")
        if m:
            hits.append({"type": "credential", "severity": "critical",
                         "kind": label, "match": m.group(0)[:40]})
    return hits


def scan(server_url, headers=None, timeout=10, roe_guard=None,
         extra_headers=None):
    verify = _verify_tls()
    if roe_guard is not None:
        try:
            roe_guard.check_url(server_url, "POST")
        except ROEViolation as e:
            return ScanResult(
                capability="mcp_remote_probe", target=server_url,
                verdict="UNKNOWN", reason=f"ROE_BLOCK: {e}",
            )
    all_headers = dict(headers or {})
    if extra_headers:
        all_headers.update(extra_headers)
    init = _initialize(server_url, headers=all_headers, timeout=timeout,
                       verify=verify, roe_guard=roe_guard)
    if init.get("blocked"):
        return ScanResult(
            capability="mcp_remote_probe", target=server_url,
            verdict="UNKNOWN", reason=init["error"],
        )
    if not init.get("ok"):
        return ScanResult(
            capability="mcp_remote_probe", target=server_url,
            verdict="UNKNOWN",
            reason=f"MCP initialize failed: {init.get('error')}",
            evidence={"raw": init.get("raw", "")[:300]},
        )
    session = init.get("session_id")
    tools_result = _list_tools(server_url, session_id=session,
                                headers=all_headers, timeout=timeout,
                                verify=verify, roe_guard=roe_guard)
    if tools_result.get("blocked"):
        return ScanResult(
            capability="mcp_remote_probe", target=server_url,
            verdict="UNKNOWN", reason=tools_result["error"],
        )
    if not tools_result.get("ok"):
        return ScanResult(
            capability="mcp_remote_probe", target=server_url,
            verdict="SUSPICIOUS",
            reason=(f"MCP server reachable but tools/list failed: "
                    f"{tools_result.get('error')}"),
            evidence={"server_info": init.get("server_info")},
        )
    tools = tools_result.get("tools") or []
    findings = []
    for tool in tools:
        name = tool.get("name") or ""
        desc = tool.get("description") or ""
        hits = _scan_description(name, desc)
        if hits:
            findings.append({"tool": name, "hits": hits,
                             "description_preview": desc[:200]})
    if findings:
        return ScanResult(
            capability="mcp_remote_probe", target=server_url,
            verdict="VULNERABLE", severity="critical",
            reason=(f"{len(findings)} of {len(tools)} tool(s) flagged "
                    f"for poisoning or credential exposure"),
            evidence={"findings": findings,
                      "server_info": init.get("server_info"),
                      "tool_count": len(tools)},
        )
    return ScanResult(
        capability="mcp_remote_probe", target=server_url,
        verdict="PASS", severity="info",
        reason=(f"enumerated {len(tools)} tool(s); no poisoning or "
                f"credentials"),
        evidence={"server_info": init.get("server_info"),
                  "tool_names": [t.get("name") for t in tools][:50]},
    )


def _tool_mcp_remote_probe(orch, args):
    url = args.get("url") or args.get("server_url")
    if not url:
        return {"verdict": "UNKNOWN",
                "reason": "mcp_remote_probe requires url or server_url"}
    try:
        r = scan(url, roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": (f"mcp_remote_probe failed: "
                           f"{type(e).__name__}: {e}"),
                "evidence": {}}
    return {"verdict": r["verdict"], "reason": r.reason,
            "evidence": r.evidence or {}}


register_tool("mcp_remote_probe", _tool_mcp_remote_probe)


__all__ = ["scan", "CAPABILITY", "_scan_description",
           "_try_parse_jsonrpc_response"]
