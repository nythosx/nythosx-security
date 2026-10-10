from claude_agent_sdk import tool

from engine import weak_password_policy, lockout_probe, weak_credential_enum
from engine.config import load_engine
from engine.contract import Capability
from engine.roe_guard import ROEGuard
from engine import registry


for _cap in (weak_password_policy.CAPABILITY,
              lockout_probe.CAPABILITY,
              weak_credential_enum.CAPABILITY):
    try:
        registry.register(_cap)
    except Exception:
        pass


@tool(
    "weak_password_scan",
    "Test the account password policy by attempting to set the authenticated "
    "user's password to weak values (short, common, dictionary). Requires a "
    "valid session (--auth or --session).",
    {"target_url": str, "change_path": str, "current_password": str},
)
async def tool_weak_password_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = weak_password_policy.scan(
            args["target_url"],
            change_path=args.get("change_path") or None,
            current_password=args.get("current_password") or None,
            roe_guard=guard,
        )
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"weak_password_scan error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}


@tool(
    "lockout_probe",
    "Detect missing account lockout by sending repeated bad logins. Stops "
    "early on 423/429 or lockout markers. Idempotent=False.",
    {"login_url": str, "username": str, "attempts": int},
)
async def tool_lockout_probe(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = lockout_probe.scan(
            args["login_url"], args["username"],
            attempts=int(args.get("attempts") or 10),
            roe_guard=guard,
        )
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"lockout_probe error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}


@tool(
    "weak_credential_enum",
    "Attempt a curated list of common credentials. Destructive, requires "
    "written_authorization. Disabled unless weak_password.opt_in_destructive "
    "is true in engine.yaml.",
    {"login_url": str, "usernames_csv": str, "max_passwords": int},
)
async def tool_weak_credential_enum(args):
    users = [u.strip() for u in (args.get("usernames_csv") or "").split(",") if u.strip()]
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = weak_credential_enum.scan(
            args["login_url"],
            usernames=users or None,
            max_passwords=int(args.get("max_passwords") or 20),
            roe_guard=guard,
        )
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"weak_credential_enum error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
