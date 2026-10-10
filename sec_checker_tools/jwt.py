from claude_agent_sdk import tool
from engine import jwt_attacks
from engine.config import load_engine
from engine.roe_guard import ROEGuard


@tool(
    "jwt_attack",
    "Run an advanced JWT security attack suite against a JWT-protected endpoint. "
    "Tests alg:none bypass (all case variants), RS256->HS256 algorithm confusion, "
    "kid header SQL injection and path traversal, embedded JWK injection, and weak "
    "HMAC secret cracking. Use when the target uses JWT for authentication and you "
    "have a captured token.",
    {
        "target_url": str,
        "token": str,
        "public_key_pem": str,
        "method": str,
    },
)
async def tool_jwt_attack(args):
    target = args["target_url"]
    token = args["token"]
    public_key = args.get("public_key_pem") or None
    method = args.get("method") or "GET"
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        out = jwt_attacks.run_attack_suite(
            target, token, method=method, public_key=public_key, roe_guard=guard,
        )
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"jwt_attack failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    if out.get("error"):
        return {
            "content": [{"type": "text", "text": f"jwt_attack error: {out['error']}"}],
            "isError": True,
        }
    results = out.get("results") or []
    counts = out.get("summary") or {}
    lines = [
        f"JWT Attack Suite: {target}",
        f"Algorithm: {out['decoded']['header'].get('alg')}",
        f"Vulnerable: {counts.get('VULNERABLE', 0)} | "
        f"Suspicious: {counts.get('SUSPICIOUS', 0)} | "
        f"Pass: {counts.get('PASS', 0)} | "
        f"Unknown: {counts.get('UNKNOWN', 0)}",
        "",
    ]
    for r in results:
        lines.append(f"[{r['verdict']}] {r['vector']}: {r.get('reason', '')[:120]}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {"results": results, "summary": counts},
    }


@tool(
    "jwt_decode",
    "Decode a JWT token and report its header and payload. Also flags common "
    "red flags: alg:none, unsafe kid values, jku/x5u headers, embedded jwk, "
    "missing exp/nbf claims, and suspiciously short signatures.",
    {
        "token": str,
    },
)
async def tool_jwt_decode(args):
    token = args["token"]
    decoded = jwt_attacks.decode_jwt(token)
    if not decoded:
        return {
            "content": [{"type": "text", "text": "Invalid JWT format"}],
            "isError": True,
        }
    crack = jwt_attacks.crack_hmac(token)
    lines = [
        f"Header: {decoded['header']}",
        f"Payload: {decoded['payload']}",
        f"Signature length: {len(decoded['signature'])}",
        f"Crackable: {crack.get('crackable') if crack else False}",
        f"Weak secret: {crack.get('secret') if crack else None}",
    ]
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": decoded,
    }
