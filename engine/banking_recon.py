import re

from .chain_engine import register_tool
from .util import join_smart


def _budget_dead():
    try:
        from . import budget
        return budget.snapshot_human().get("reason") is not None
    except Exception:
        return False

BANKING_PATHS = [
    "/api/v1/accounts",
    "/api/v1/accounts/1",
    "/api/v1/accounts/2",
    "/api/v1/transactions",
    "/api/v1/transactions/1",
    "/api/v1/customers",
    "/api/v1/customers/1",
    "/api/v1/users",
    "/api/v1/users/1",
    "/api/v1/balance",
    "/api/v1/statements",
    "/api/v1/statements/1",
    "/api/v1/cards",
    "/api/v1/cards/1",
    "/api/v1/loans",
    "/api/v1/payments",
    "/api/v1/transfers",
    "/api/v1/beneficiaries",
    "/api/v1/beneficiaries/1",
    "/api/v2/accounts",
    "/api/v2/transactions",
    "/swagger.json",
    "/openapi.json",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api/docs",
    "/api/openapi.json",
]

ID_PATH_RE = re.compile(r"/\d+(?:/|$)")

_FACT_MAP = [
    ("account", "has_accounts_endpoint", "accounts_url"),
    ("transaction", "has_transactions_endpoint", "transactions_url"),
    ("customer", "has_customers_endpoint", "customers_url"),
    ("users", "has_users_endpoint", "users_url"),
    ("balance", "has_balance_endpoint", "balance_url"),
    ("statement", "has_statements_endpoint", "statements_url"),
    ("card", "has_cards_endpoint", "cards_url"),
    ("loan", "has_loans_endpoint", "loans_url"),
    ("payment", "has_payments_endpoint", "payments_url"),
    ("transfer", "has_transfers_endpoint", "transfers_url"),
    ("beneficiar", "has_beneficiaries_endpoint", "beneficiaries_url"),
]

_SPEC_MARKERS = ("swagger", "openapi", "api-docs", "api/docs")


def probe_banking_paths(orch, timeout=5):
    from . import discovery

    api_base = (orch.get_fact("api_base") or orch.target or "").rstrip("/")
    if not api_base:
        return {"probed": 0, "hits": 0, "facts_added": []}

    before = set(orch.facts.keys())
    hits = 0

    for path in BANKING_PATHS:
        if _budget_dead():
            orch._warn("budget_exceeded",
                       "banking recon aborted: duration/request budget exhausted")
            break
        url = join_smart(api_base, path)
        try:
            r = discovery.fetch(url, timeout=timeout)
        except Exception:
            continue
        if r is None or r.status_code != 200:
            continue
        ct = (r.headers.get("Content-Type") or "").lower()
        if "json" not in ct and "<html" in (r.text or "")[:200].lower():
            continue
        hits += 1
        low = path.lower()
        if any(m in low for m in _SPEC_MARKERS):
            orch.add_fact("has_openapi", True, source="banking_recon")
            orch.set_context("openapi_url", url)
            continue
        for needle, fact, ctx in _FACT_MAP:
            if needle in low:
                orch.add_fact(fact, True, source="banking_recon")
                orch.set_context(ctx, url)
                if ID_PATH_RE.search(low):
                    orch.set_context(ctx + "_with_id", url)
                break

    after = set(orch.facts.keys())
    added = sorted(after - before)
    orch.recon.setdefault("banking_recon", {})
    orch.recon["banking_recon"] = {
        "probed": len(BANKING_PATHS),
        "hits": hits,
        "facts_added": added,
    }
    return orch.recon["banking_recon"]


def _tool_banking_recon(orch, args):
    timeout = int(args.get("timeout") or 5)
    result = probe_banking_paths(orch, timeout=timeout)
    added = result.get("facts_added") or []
    hits = result.get("hits") or 0
    if not added:
        if hits == 0:
            return {
                "verdict": "PASS",
                "reason": f"no banking endpoints responded 200 across {result.get('probed', 0)} path(s)",
                "evidence": result,
            }
        return {
            "verdict": "SUSPICIOUS",
            "reason": f"{hits} banking endpoint(s) responded 200 but no known category matched",
            "evidence": result,
        }
    return {
        "verdict": "SUSPICIOUS",
        "reason": f"detected {len(added)} banking fact(s) from {hits} live path(s): {', '.join(added[:6])}",
        "evidence": result,
    }


register_tool("banking_recon", _tool_banking_recon)
