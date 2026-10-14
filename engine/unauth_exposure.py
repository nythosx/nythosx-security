from .chain_engine import register_tool
from .config import load_engine
from .contract import DataRow
from .util import unwrap_rows, join_smart
from . import http as _http


def _budget_dead():
    try:
        from . import budget
        return budget.snapshot_human().get("reason") is not None
    except Exception:
        return False

UNAUTH_PATHS = [
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
    "/api/v1/cards",
    "/api/v1/cards/1",
    "/api/v1/loans",
    "/api/v1/payments",
    "/api/v1/transfers",
    "/api/v1/beneficiaries",
    "/check_balance/1",
    "/accounts",
    "/transactions",
    "/customers",
    "/balance",
]

SENSITIVE_FIELDS = (
    "account", "balance", "amount", "transaction", "card", "pan",
    "ssn", "email", "phone", "address", "iban", "cvv", "kyc",
    "loan", "payment", "transfer", "beneficiary", "customer",
)


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _cfg():
    try:
        cfg = load_engine() or {}
        return cfg.get("banking") or {}
    except Exception:
        return {}


def _has_sensitive(row):
    for k in row.keys():
        kl = str(k).lower()
        if any(h in kl for h in SENSITIVE_FIELDS):
            return True
    return False


def probe(base_url, paths=None, roe_guard=None, timeout=8,
          max_rows=5, max_paths=40):
    verify = _verify_tls()
    base = base_url.rstrip("/")
    path_list = (paths or UNAUTH_PATHS)[:max_paths]
    live = []
    exposed = []

    for path in path_list:
        if _budget_dead():
            break
        url = join_smart(base, path)
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.get(url, headers={"Accept": "application/json"})
        except _http.ROEBlock as e:
            return {"verdict": "UNKNOWN",
                    "reason": f"ROE_BLOCK: {e}",
                    "evidence": {"url": url}}
        except Exception:
            continue

        ct = (r.headers.get("Content-Type") or "").lower()
        if r.status_code != 200 or "json" not in ct:
            continue
        try:
            parsed = r.json()
        except Exception:
            continue
        rows = unwrap_rows(parsed)
        if not rows:
            continue
        live.append({"url": url, "rows": len(rows)})
        sensitive = [row for row in rows if _has_sensitive(row)]
        if sensitive:
            extracted = sensitive[:max_rows]
            exposed.append({
                "url": url,
                "total_rows": len(rows),
                "sensitive_rows": len(sensitive),
                "extracted": len(extracted),
                "rows": extracted,
            })

    if exposed:
        total = sum(e["extracted"] for e in exposed)
        return {
            "verdict": "VULNERABLE",
            "reason": f"{len(exposed)} unauthenticated endpoint(s) returned sensitive data ({total} row(s) extracted)",
            "evidence": {"findings": exposed, "live": live},
        }
    if live:
        return {
            "verdict": "SUSPICIOUS",
            "reason": f"{len(live)} unauth endpoint(s) returned JSON but no sensitive fields detected",
            "evidence": {"live": live},
        }
    return {
        "verdict": "PASS",
        "reason": f"no unauthenticated JSON exposure across {len(path_list)} path(s)",
        "evidence": {"probed": len(path_list)},
    }


def _tool_unauth_exposure(orch, args):
    base = args.get("base_url") or orch.get_fact("api_base") or orch.target
    paths = args.get("paths")
    if isinstance(paths, str):
        paths = [p.strip() for p in paths.split(",") if p.strip()]
    result = probe(base, paths=paths, roe_guard=orch.roe_guard,
                   timeout=int(args.get("timeout") or 8),
                   max_rows=int(args.get("max_rows") or 5),
                   max_paths=int(args.get("max_paths") or 40))

    evidence = dict(result.get("evidence") or {})
    data_rows = []
    for entry in evidence.get("findings") or []:
        data_rows.append(DataRow(
            endpoint=entry["url"], method="GET", status=200,
            total_rows=entry["total_rows"],
            extracted=entry["extracted"],
            rows=entry["rows"], raw_rows=entry["rows"],
            auth_used="unauthenticated",
        ).to_dict())

    out = {
        "verdict": result.get("verdict", "UNKNOWN"),
        "reason": result.get("reason", ""),
        "evidence": evidence,
    }
    if data_rows:
        out["data_rows"] = data_rows
    return out


register_tool("unauth_exposure", _tool_unauth_exposure)
