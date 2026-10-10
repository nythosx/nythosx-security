from claude_agent_sdk import tool
from engine import bizlogic
from engine.roe_guard import ROEGuard
from engine.config import load_engine


@tool(
    "bizlogic_scan",
    "Detect business logic flaws. Probes: (1) price/quantity tampering "
    "(negative, zero, integer overflow, type confusion, NaN), (2) mass "
    "assignment (inject role/is_admin/balance fields), (3) multi-step "
    "workflow bypass (skip payment/MFA/verification steps, set terminal "
    "states directly), (4) race-condition-gated logic (concurrent coupon "
    "redemption, transfer, one-time operations), (5) coupon reuse (sequential "
    "application), (6) verification bypass (access protected paths without "
    "prior verification). Use when the target has e-commerce, checkout, "
    "coupon, refund, subscription, transfer, or multi-step approval flows. "
    "Requires explicit endpoint configuration to avoid guessing.",
    {
        "base_url": str,
        "price_endpoint": str,
        "price_body_json": str,
        "mass_endpoint": str,
        "mass_body_json": str,
        "race_endpoint": str,
        "race_body_json": str,
        "coupon_code": str,
        "protected_path": str,
    },
)
async def tool_bizlogic_scan(args):
    base = args["base_url"]
    endpoints = {}
    if args.get("price_endpoint") and args.get("price_body_json"):
        try:
            endpoints["price_endpoint"] = {
                "url": args["price_endpoint"], "method": "POST",
                "baseline_body": __import__("json").loads(args["price_body_json"]),
            }
        except Exception:
            pass
    if args.get("mass_endpoint") and args.get("mass_body_json"):
        try:
            endpoints["mass_assign_endpoint"] = {
                "url": args["mass_endpoint"], "method": "POST",
                "baseline_body": __import__("json").loads(args["mass_body_json"]),
            }
        except Exception:
            pass
    if args.get("race_endpoint"):
        endpoints["race_endpoint"] = {
            "path": args["race_endpoint"],
            "body": (__import__("json").loads(args["race_body_json"])
                     if args.get("race_body_json") else None),
            "count": 20,
        }
    if args.get("coupon_code"):
        endpoints["coupon"] = {"code": args["coupon_code"]}
    if args.get("protected_path"):
        endpoints["protected_path"] = args["protected_path"]

    if not endpoints:
        return {
            "content": [{"type": "text",
                         "text": "bizlogic_scan: at least one endpoint must be provided"}],
            "isError": True,
        }
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        out = bizlogic.scan(base, roe_guard=guard, endpoints=endpoints)
    except Exception as e:
        return {
            "content": [{"type": "text",
                         "text": f"bizlogic_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    lines = [f"Business logic scan: {base}",
             f"Overall: {out.get('verdict')}",
             f"Reason: {out.get('reason', '')}", ""]
    for name, r in (out.get("probes") or {}).items():
        lines.append(f"[{r.get('verdict')}] {name}: {r.get('reason', '')[:140]}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": out,
    }
