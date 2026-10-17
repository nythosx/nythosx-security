"""Tier-2 Phase 2 wiring: H2 tier-2 + desync tools + oracles."""
from .chain_engine import register_tool
from .h2_t2 import scan as h2_t2_scan
from .desync import tunnel as desync_tunnel
from .desync import queue_poison as desync_queue
from . import oracle as _oracle


def _tool_h2_t2_scan(orch, args):
    url = args.get("url") or orch.target
    timeout = int(args.get("timeout") or 6)
    probes = args.get("probes")
    if isinstance(probes, str):
        probes = [p.strip() for p in probes.split(",") if p.strip()]
    try:
        result = h2_t2_scan(url, timeout=timeout,
                             roe_guard=getattr(orch, "roe_guard", None),
                             probes=probes)
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "h2_t2_scan failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    if result.get("h2_desync"):
        try:
            orch.add_fact("h2_desync_confirmed", True,
                          source="h2_t2_scan")
        except Exception:
            pass
    return {"verdict": result.get("verdict", "UNKNOWN"),
            "reason": result.get("reason", ""),
            "evidence": result.get("evidence", {})}


def _tool_desync_tunnel(orch, args):
    url = args.get("url") or orch.target
    target_path = args.get("target_path") or "/admin"
    surface = args.get("desync_surface")
    if surface is None:
        try:
            surface = orch.get_fact("desync_surface")
        except Exception:
            surface = None
    timeout = int(args.get("timeout") or 6)
    max_smuggled = int(args.get("max_smuggled") or 10)
    try:
        result = desync_tunnel.tunnel_to_path(
            url, target_path, desync_surface=surface,
            timeout=timeout, max_smuggled=max_smuggled,
            roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "desync_tunnel failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    if result.get("tunnel_confirmed"):
        try:
            orch.add_fact("desync_tunnel_confirmed", True,
                          source="desync_tunnel")
            orch.add_fact("has_acl_bypass_via_desync", True,
                          source="desync_tunnel")
        except Exception:
            pass
    return {"verdict": result.get("verdict", "UNKNOWN"),
            "reason": result.get("reason", ""),
            "evidence": result.get("evidence", {})}


def _tool_desync_queue_poison(orch, args):
    url = args.get("url") or orch.target
    timeout = int(args.get("timeout") or 6)
    expected = args.get("expected_normal_body") or "ok"
    try:
        result = desync_queue.probe(
            url, timeout=timeout, expected_normal_body=expected,
            roe_guard=getattr(orch, "roe_guard", None))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": "desync_queue_poison failed: %s: %s"
                          % (type(e).__name__, e),
                "evidence": {}}
    if result.get("queue_poisoned"):
        try:
            orch.add_fact("queue_poisoned", True,
                          source="desync_queue_poison")
        except Exception:
            pass
    return {"verdict": result.get("verdict", "UNKNOWN"),
            "reason": result.get("reason", ""),
            "evidence": result.get("evidence", {})}


register_tool("h2_t2_scan", _tool_h2_t2_scan,
              provides=["h2_desync_confirmed"])
register_tool("desync_tunnel", _tool_desync_tunnel,
              provides=["desync_tunnel_confirmed",
                        "has_acl_bypass_via_desync"])
register_tool("desync_queue_poison", _tool_desync_queue_poison,
              provides=["queue_poisoned"])


def _oracle_desync_surface_confirmed(oracle, context):
    for s in (context.get("steps") or []):
        body = s.get("body") or ""
        if "tunnel_confirmed" in body or "smuggled_detected" in body:
            return {
                "verdict": oracle.get("verdict", "VULNERABLE"),
                "reason": "desync tunnel smuggled a request",
                "evidence": {"preview": body[:400]},
            }
    return {"verdict": "PASS",
            "reason": "no desync tunnel confirmation in context",
            "evidence": {}}


def _oracle_h2_h1_divergence(oracle, context):
    for s in (context.get("steps") or []):
        body = s.get("body") or ""
        if ("h2_desync" in body or "CL:0 with DATA" in body
                or "CRLF-containing :path" in body):
            return {
                "verdict": oracle.get("verdict", "VULNERABLE"),
                "reason": "H2 accepts an h1-illegal request",
                "evidence": {"preview": body[:400]},
            }
    return {"verdict": "PASS",
            "reason": "no H2/h1 divergence in context",
            "evidence": {}}


def _oracle_queue_poison_confirmed(oracle, context):
    for s in (context.get("steps") or []):
        body = s.get("body") or ""
        if "queue_poisoned" in body and "true" in body.lower():
            return {
                "verdict": oracle.get("verdict", "VULNERABLE"),
                "reason": "queue proof marker interleaved with victim response",
                "evidence": {"preview": body[:400]},
            }
    return {"verdict": "PASS",
            "reason": "no queue poisoning confirmed",
            "evidence": {}}


_oracle._HANDLERS.update({
    "desync_surface_confirmed": _oracle_desync_surface_confirmed,
    "h2_h1_divergence": _oracle_h2_h1_divergence,
    "queue_poison_confirmed": _oracle_queue_poison_confirmed,
})
