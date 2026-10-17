"""Tier-2 Phase 1 wiring: parser differential tools + oracles."""
from .chain_engine import register_tool
from .parserdiff import boundary_diff, bodyparser_diff, charset_diff
from . import oracle as _oracle


def _tool_parser_boundary_diff(orch, args):
    url = args.get("url") or orch.target
    timeout = int(args.get("timeout") or 5)
    try:
        result = boundary_diff.extract_desync_surface(
            url, timeout=timeout, roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "parser_boundary_diff failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    surface = result.get("desync_surface")
    if surface:
        try:
            orch.add_fact("desync_surface", surface,
                          source="parser_boundary_diff")
        except Exception:
            pass
    return {"verdict": result.get("verdict", "UNKNOWN"),
            "reason": result.get("reason", ""),
            "evidence": result.get("evidence", {})}


def _tool_parser_bodyparser_diff(orch, args):
    url = args.get("url") or orch.target
    payload = args.get("payload")
    if not isinstance(payload, dict):
        payload = None
    timeout = int(args.get("timeout") or 8)
    try:
        result = bodyparser_diff.detect_bodyparser_divergence(
            url, payload=payload, timeout=timeout,
            roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "parser_bodyparser_diff failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    if result.get("verdict") == "VULNERABLE":
        try:
            orch.add_fact("parser_divergence_found", True,
                          source="parser_bodyparser_diff")
        except Exception:
            pass
    return {"verdict": result.get("verdict", "UNKNOWN"),
            "reason": result.get("reason", ""),
            "evidence": result.get("evidence", {})}


def _tool_parser_charset_diff(orch, args):
    url = args.get("url") or orch.target
    param = args.get("param") or "value"
    payload = args.get("payload") or "café"
    timeout = int(args.get("timeout") or 8)
    try:
        result = charset_diff.detect_charset_divergence(
            url, param=param, payload=payload, timeout=timeout,
            roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "parser_charset_diff failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    if result.get("verdict") == "VULNERABLE":
        try:
            orch.add_fact("charset_divergence_found", True,
                          source="parser_charset_diff")
        except Exception:
            pass
    return {"verdict": result.get("verdict", "UNKNOWN"),
            "reason": result.get("reason", ""),
            "evidence": result.get("evidence", {})}


register_tool("parser_boundary_diff", _tool_parser_boundary_diff,
              provides=["desync_surface"])
register_tool("parser_bodyparser_diff", _tool_parser_bodyparser_diff,
              provides=["parser_divergence_found"])
register_tool("parser_charset_diff", _tool_parser_charset_diff,
              provides=["charset_divergence_found"])


def _oracle_parser_divergence(oracle, context):
    for s in (context.get("steps") or []):
        body = (s.get("body") or "").lower()
        if "accepted" in body and "rejected" in body:
            try:
                import json as _json
                data = _json.loads(s.get("body") or "")
            except Exception:
                data = None
            if isinstance(data, dict) and data.get("divergence"):
                return {
                    "verdict": oracle.get("verdict", "VULNERABLE"),
                    "reason": "parser accepted different serializations",
                    "evidence": data,
                }
    return {"verdict": "PASS", "reason": "no parser divergence seen",
            "evidence": {}}


def _oracle_charset_divergence(oracle, context):
    for s in (context.get("steps") or []):
        body = (s.get("body") or "").lower()
        if "charset_sensitive" in body or "charset normalization" in body:
            try:
                import json as _json
                data = _json.loads(s.get("body") or "")
            except Exception:
                data = None
            if isinstance(data, dict) and data.get("charset_sensitive"):
                return {
                    "verdict": oracle.get("verdict", "VULNERABLE"),
                    "reason": "charset normalization changed server response",
                    "evidence": data,
                }
    return {"verdict": "PASS", "reason": "no charset divergence seen",
            "evidence": {}}


_oracle._HANDLERS.update({
    "parser_divergence": _oracle_parser_divergence,
    "charset_divergence": _oracle_charset_divergence,
})
