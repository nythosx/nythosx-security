import base64
import json

from .chain_engine import register_tool
from .config import load_engine
from .contract import DataRow
from .util import unwrap_rows, join_smart
from . import http as _http

ID_PATH_RE = __import__("re").compile(r"/\d{2,}(?:/|$)")

DEFAULT_ID_ENDPOINTS = [
    "/api/v1/accounts",
    "/api/v1/accounts/1",
    "/api/v1/accounts/2",
    "/api/v1/transactions",
    "/api/v1/transactions/1",
    "/api/v1/customers",
    "/api/v1/customers/1",
    "/api/v1/users",
    "/api/v1/users/1",
    "/api/v1/statements",
    "/api/v1/statements/1",
    "/api/v1/cards",
    "/api/v1/cards/1",
    "/api/v1/beneficiaries",
    "/api/v1/beneficiaries/1",
]


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _decode_jwt_payload(token):
    if not token or token.count(".") != 2:
        return None
    try:
        payload = token.split(".")[1]
        pad = "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload + pad))
    except Exception:
        return None


def _get(base, path, token, timeout, verify):
    url = join_smart(base, path)
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(url, headers=headers)
    except _http.ROEBlock as e:
        return {"url": url, "status": None, "error": f"ROE_BLOCK: {e}",
                "roe_block": True}
    except Exception as e:
        return {"url": url, "status": None, "error": f"{type(e).__name__}: {e}"}
    ct = (r.headers.get("Content-Type") or "").lower()
    out = {"url": url, "status": r.status_code, "ct": ct, "body": r.text or ""}
    if r.status_code == 200 and "json" in ct:
        try:
            out["parsed"] = r.json()
        except Exception:
            out["parsed"] = None
    return out


def _rows(resp):
    if not resp or resp.get("status") != 200:
        return []
    parsed = resp.get("parsed")
    if parsed is None:
        return []
    return unwrap_rows(parsed)


def _discover_id_endpoints(orch, base):
    recon_paths = (orch.recon.get("api_paths") or []) + \
                  (orch.recon.get("live_paths") or [])
    id_paths = [p for p in recon_paths
                if ID_PATH_RE.search(str(p)) and "/api" in str(p).lower()]
    if not id_paths:
        return list(DEFAULT_ID_ENDPOINTS)
    uniq = []
    seen = set()
    for p in id_paths:
        s = str(p)
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq[:30]


def _sequential_id_check(base, token, endpoints, timeout, verify,
                         max_rows=5):
    hits = []
    for path in endpoints:
        if not ID_PATH_RE.search(path):
            continue
        r1 = _get(base, path, token, timeout, verify)
        if r1.get("status") != 200:
            continue
        rows = _rows(r1)
        if not rows:
            continue
        hits.append({
            "url": r1["url"],
            "total_rows": len(rows),
            "extracted": min(len(rows), max_rows),
            "rows": rows[:max_rows],
        })
        if len(hits) >= 5:
            break
    if hits:
        return {
            "verdict": "SUSPICIOUS",
            "reason": f"single-session sequential-ID probe returned {len(hits)} endpoint(s) with rows (possible BOLA — confirm with a second user)",
            "evidence": {"findings": hits, "mode": "sequential_single_session"},
        }
    return {
        "verdict": "PASS",
        "reason": "no rows from sequential-ID probe with the single available session",
        "evidence": {"mode": "sequential_single_session"},
    }


def _cross_user_check(base, token_a, token_b, endpoints, timeout, verify,
                      max_rows=5):
    findings = []
    probes = []
    for path in endpoints:
        if not path.startswith("/"):
            path = "/" + path
        ra = _get(base, path, token_a, timeout, verify)
        rb = _get(base, path, token_b, timeout, verify)
        probes.append({"path": path, "a_status": ra.get("status"),
                       "b_status": rb.get("status")})
        if ra.get("roe_block") or rb.get("roe_block"):
            return {"verdict": "UNKNOWN",
                    "reason": "ROE_BLOCK during BOLA probe",
                    "evidence": {"probes": probes}}
        if ra.get("status") != 200 or rb.get("status") != 200:
            continue
        rows_a = _rows(ra)
        rows_b = _rows(rb)
        if not rows_a or not rows_b:
            continue
        if ra.get("body") == rb.get("body"):
            continue
        findings.append({
            "url": rb["url"],
            "path": path,
            "status": 200,
            "a_rows": len(rows_a),
            "b_rows": len(rows_b),
            "b_extracted": min(len(rows_b), max_rows),
            "b_rows_sample": rows_b[:max_rows],
        })
        if len(findings) >= 5:
            break

    if findings:
        total = sum(f["b_extracted"] for f in findings)
        return {
            "verdict": "VULNERABLE",
            "reason": f"user-B token returned distinct rows on {len(findings)} endpoint(s) ({total} row(s) extracted)",
            "evidence": {"findings": findings, "probes": probes,
                         "mode": "cross_user"},
        }
    return {
        "verdict": "PASS",
        "reason": "no cross-user data exposure detected between the two sessions",
        "evidence": {"mode": "cross_user", "probes": probes},
    }


def _tool_bola_scan(orch, args):
    base = args.get("base_url") or orch.get_fact("api_base") or orch.target
    if not base:
        return {"verdict": "UNKNOWN", "reason": "no base_url available",
                "evidence": {}}

    token_a = args.get("token_a") or orch.get_context("jwt_token") or ""
    token_b = args.get("token_b") or orch.get_context("jwt_token_b") or ""

    if not token_a:
        return {"verdict": "UNKNOWN",
                "reason": "bola_scan requires an authenticated session for user-a; no jwt_token in context",
                "evidence": {}}

    endpoints = args.get("endpoints")
    if isinstance(endpoints, str):
        endpoints = [e.strip() for e in endpoints.split(",") if e.strip()]
    if not endpoints:
        endpoints = _discover_id_endpoints(orch, base)

    timeout = int(args.get("timeout") or 10)
    max_rows = int(args.get("max_rows") or 5)
    verify = _verify_tls()

    payload_a = _decode_jwt_payload(token_a)
    identity_a = None
    if payload_a:
        for k in ("sub", "user_id", "account_id", "email", "username", "id"):
            if payload_a.get(k):
                identity_a = payload_a[k]
                break

    if token_b:
        result = _cross_user_check(base, token_a, token_b, endpoints,
                                   timeout, verify, max_rows=max_rows)
    else:
        result = _sequential_id_check(base, token_a, endpoints,
                                      timeout, verify, max_rows=max_rows)

    evidence = dict(result.get("evidence") or {})
    evidence["identity_a"] = identity_a
    evidence["two_sessions"] = bool(token_b)

    data_rows = []
    for f in evidence.get("findings") or []:
        rows = f.get("b_rows_sample") or f.get("rows") or []
        if not rows:
            continue
        data_rows.append(DataRow(
            endpoint=f.get("url") or f.get("path") or base,
            method="GET", status=200,
            total_rows=f.get("b_rows") or f.get("total_rows") or len(rows),
            extracted=len(rows), rows=rows, raw_rows=rows,
            auth_used="user-b" if token_b else "user-a",
        ).to_dict())

    out = {
        "verdict": result.get("verdict", "UNKNOWN"),
        "reason": result.get("reason", ""),
        "evidence": evidence,
    }
    if data_rows:
        out["data_rows"] = data_rows
    return out


register_tool("bola_scan", _tool_bola_scan)


def harvest_sequential_ids(base_url, endpoint_template, token,
                           id_range=range(1, 501), max_records=100,
                           headers=None, timeout=10, roe_guard=None,
                           mode="probe", target=None, hard_ceiling=5000):
    """Walk the ID space of an endpoint and collect records.

    endpoint_template: path with {id} placeholder, e.g. /api/orders/{id}
    token: bearer token for user B
    Returns list of {id, owner_field, owner_value, rows}
    """
    import re as _re
    harvested = []
    endpoint_template = endpoint_template.replace("<int:id>", "{id}")
    if "{id}" not in endpoint_template and not _re.search(r"/\d+(?=/?$)", endpoint_template):
        return harvested

    consecutive_miss = 0
    for obj_id in id_range:
        if mode == "probe" and len(harvested) >= max_records:
            break
        if len(harvested) >= hard_ceiling:
            break
        path = endpoint_template
        if "{id}" in path:
            path = path.replace("{id}", str(obj_id))
        elif _re.search(r"/\d+(?=/?$)", path):
            path = _re.sub(r"/\d+(?=/?$)", "/" + str(obj_id), path, count=1)
        r = _get(base_url, path, token, timeout, False)
        status = r.get("status")
        if status in (429, 403):
            break
        if status != 200:
            consecutive_miss += 1
            if mode == "harvest" and consecutive_miss >= 20:
                break
            continue
        rows = _rows(r)
        if not rows:
            consecutive_miss += 1
            if mode == "harvest" and consecutive_miss >= 20:
                break
            continue
        consecutive_miss = 0
        sample = rows[0] if isinstance(rows[0], dict) else {}
        owner_field = None
        owner_value = None
        for k in ("owner_id", "user_id", "account_id", "customer_id",
                   "email", "owner", "username"):
            if k in sample and sample.get(k) is not None:
                owner_field = k
                owner_value = sample.get(k)
                break
        entry = {"id": obj_id, "owner_field": owner_field,
                 "owner_value": owner_value, "rows": rows[:3]}
        harvested.append(entry)
        if mode == "harvest" and target:
            try:
                from . import artifacts
                artifacts.write(target, "bola_record", entry)
            except Exception:
                pass
    return harvested


def _tool_bola_harvest(orch, args):
    base = args.get("base_url") or orch.get_fact("api_base") or orch.target
    template = args.get("endpoint_template")
    if not template:
        return {"verdict": "UNKNOWN",
                "reason": "bola_harvest requires endpoint_template with {id}"}
    token = (args.get("token") or orch.get_context("jwt_token")
             or orch.get_context("jwt_token_b"))
    if not token:
        return {"verdict": "UNKNOWN",
                "reason": "bola_harvest requires a bearer token"}
    max_records = int(args.get("max_records") or 100)
    endpoint_template = template.replace("{{ api_base }}", base)
    mode = args.get("mode") or ("harvest" if getattr(orch, "harvest_mode", False) else "probe")
    harvested = harvest_sequential_ids(
        base, endpoint_template, token,
        max_records=max_records,
        timeout=int(args.get("timeout") or 10),
        roe_guard=orch.roe_guard,
        mode=mode, target=orch.target,
    )
    if not harvested:
        return {"verdict": "PASS",
                "reason": f"no records harvested across ID walk of {template}",
                "evidence": {"endpoint": endpoint_template}}
    owners = set()
    for h in harvested:
        if h.get("owner_value") is not None:
            owners.add(str(h["owner_value"]))
    sample_fields = []
    if harvested and harvested[0].get("rows"):
        sample_fields = list(harvested[0]["rows"][0].keys())[:8]
    verdict = "VULNERABLE" if len(owners) >= 2 or len(harvested) >= 3 \
              else "SUSPICIOUS"
    return {
        "verdict": verdict,
        "reason": (f"harvested {len(harvested)} record(s) across "
                    f"{len(owners)} distinct owner(s) via {template}"),
        "evidence": {
            "endpoint": endpoint_template,
            "total_rows": len(harvested),
            "distinct_owners": len(owners),
            "sample_fields": sample_fields,
            "extracted_records": [{"id": h["id"], "owner": h.get("owner_value"),
                                    "rows": h["rows"]}
                                   for h in harvested[:10]],
        },
    }


register_tool("bola_harvest", _tool_bola_harvest)
