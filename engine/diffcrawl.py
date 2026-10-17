"""Phase 2 — Auth-Context Differential Crawler.

Crawls the target once per auth context (anon, user_a, user_b, and
optionally admin), then diffs the three endpoint/response sets to surface
access-control defects:

  * admin ∩ anon reachable      -> missing access control on sensitive surface
  * user_a reaches user_b's resource by ID substitution -> IDOR / BOLA
  * endpoints in admin but absent in user crawl -> authz enforced (PASS)

Credentials live in configs/diffcrawl.creds.yaml (gitignored); a redacted
diffcrawl.creds.example.yaml ships in the repo. Every request goes through
engine.http (scope gate + shared rate limiter). ID substitution is bounded:
only the two operator-owned test accounts' known IDs plus sequentially
adjacent integers within ±2, capped at 6 requests per endpoint.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import auth_flow
from .http_client import HttpClient
from .roe_guard import ROEGuard, ROEViolation

ROOT = Path(__file__).parent.parent.absolute()
DEFAULT_CREDS = ROOT / "configs" / "diffcrawl.creds.yaml"

ID_SUBST_NEIGHBOR_BOUND = 2
MAX_REQUESTS_PER_ENDPOINT = 6

_ID_TYPED_NAMES = {"id", "user_id", "userid", "account_id", "accountid",
                   "doc_id", "docid", "order_id", "orderid", "uid", "pid"}


@dataclass
class SessionContext:
    name: str
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    known_ids: list = field(default_factory=list)

    def client(self, verify=True):
        return HttpClient(default_headers=dict(self.headers),
                          cookies=dict(self.cookies), verify=verify)


def load_creds(path=None):
    import yaml
    p = Path(path) if path else DEFAULT_CREDS
    if not p.exists():
        return None
    with open(p, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def creds_from_broker(broker):
    if broker is None:
        return None
    try:
        a = broker.get_identity("user_a")
        b = broker.get_identity("user_b")
    except Exception:
        return None
    if not (a and b):
        return None
    return {
        "login": {
            "url": a.login_url or "",
            "type": "json",
            "username_field": "email",
            "password_field": "password",
            "token_path": "token",
        },
        "accounts": {
            "user_a": {
                "username": a.username,
                "password": a.password,
                "known_ids": list(a.known_ids),
            },
            "user_b": {
                "username": b.username,
                "password": b.password,
                "known_ids": list(b.known_ids),
            },
        },
    }


def build_sessions(creds, verify=True):
    """Return {context_name: SessionContext}. anon is always present."""
    sessions = {"anon": SessionContext("anon")}
    if not creds:
        return sessions
    login = creds.get("login") or {}
    accounts = creds.get("accounts") or {}
    for name, acct in accounts.items():
        if name not in ("user_a", "user_b", "admin"):
            continue
        known = [i for i in (acct.get("known_ids") or [])]
        if not login.get("url"):
            sessions[name] = SessionContext(name, known_ids=known)
            continue
        try:
            session = auth_flow.perform_login(
                login["url"],
                acct.get("username") or acct.get("email") or name,
                acct.get("password") or "",
                login_type=login.get("type", "json"),
                username_field=login.get("username_field", "email"),
                password_field=login.get("password_field", "password"),
                token_path=login.get("token_path"),
                verify=verify,
            )
        except Exception:
            session = {}
        sessions[name] = SessionContext(
            name,
            headers=auth_flow.build_headers_from_session(session),
            cookies=auth_flow.build_cookies_from_session(session),
            known_ids=known,
        )
    return sessions


def _param_signature(path, params):
    keys = sorted((params or {}).keys())
    return "|".join(keys)


def endpoint_key(method, path, params=None):
    return f"{method.upper()} {path} [{_param_signature(path, params)}]"


def _reachable(resp):
    status = (resp or {}).get("status")
    return status is not None and 200 <= int(status) < 300


def crawl_context(base_url, session, endpoints, roe_guard=None, verify=True):
    """Request each endpoint under one session. Returns {key: record}."""
    out = {}
    client = session.client(verify=verify)
    try:
        for ep in endpoints:
            method = ep.get("method", "GET").upper()
            path = ep.get("path", "/")
            params = ep.get("params")
            url = base_url.rstrip("/") + path
            if roe_guard is not None:
                try:
                    roe_guard.check_url(url, method)
                except ROEViolation:
                    continue
            resp = client.request(method, url, params=params)
            key = endpoint_key(method, path, params)
            out[key] = {
                "method": method, "path": path, "url": url,
                "params": params or {},
                "status": resp.get("status"),
                "body": resp.get("body") or "",
                "body_hash": resp.get("body_hash"),
                "reachable": _reachable(resp),
            }
    finally:
        client.close()
    return out


def _id_typed_params(ep):
    names = []
    for k in (ep.get("params") or {}):
        if k.lower() in _ID_TYPED_NAMES:
            names.append(k)
    # path-embedded id: /api/doc/{id} style endpoints flagged via id_param
    if ep.get("id_param"):
        names.append(ep["id_param"])
    return names


def _bounded_substitution_ids(own_ids, other_ids):
    """Safe ID set: the two accounts' known IDs + ±2 neighbors, capped."""
    ids = []
    for oid in (other_ids or []):
        if oid not in ids:
            ids.append(oid)
    for base in (own_ids or []):
        try:
            n = int(base)
        except (TypeError, ValueError):
            continue
        for d in range(1, ID_SUBST_NEIGHBOR_BOUND + 1):
            for cand in (n - d, n + d):
                if cand > 0 and cand not in ids:
                    ids.append(cand)
    return ids[:MAX_REQUESTS_PER_ENDPOINT]


def _substitute(path, id_value):
    """Replace a trailing /<id> or {id} placeholder in the path."""
    import re
    if "{" in path and "}" in path:
        return re.sub(r"\{[^}]+\}", str(id_value), path, count=1)
    return re.sub(r"/\d+(?=/?$)", "/" + str(id_value), path)


def id_substitution_candidates(base_url, sessions, endpoints,
                               roe_guard=None, verify=True):
    """user_a substitutes user_b's IDs; distinct 200 body -> IDOR/BOLA."""
    candidates = []
    user_a = sessions.get("user_a")
    user_b = sessions.get("user_b")
    if not user_a or not user_b:
        return candidates
    client = user_a.client(verify=verify)
    try:
        for ep in endpoints:
            id_names = _id_typed_params(ep)
            if not id_names and not ep.get("id_param"):
                continue
            method = ep.get("method", "GET").upper()
            path_tmpl = ep.get("path", "/")
            subst_ids = _bounded_substitution_ids(user_a.known_ids,
                                                  user_b.known_ids)
            if not subst_ids:
                continue
            # baseline: user_a's own record
            own_id = (user_a.known_ids or [None])[0]
            own_resp = None
            if own_id is not None:
                own_path = _substitute(path_tmpl, own_id)
                own_url = base_url.rstrip("/") + own_path
                if _roe_ok(roe_guard, own_url, method):
                    own_resp = client.request(method, own_url)
            reqs = 0
            for sid in subst_ids:
                if reqs >= MAX_REQUESTS_PER_ENDPOINT:
                    break
                sub_path = _substitute(path_tmpl, sid)
                url = base_url.rstrip("/") + sub_path
                if not _roe_ok(roe_guard, url, method):
                    continue
                resp = client.request(method, url)
                reqs += 1
                if not _reachable(resp):
                    continue
                own_hash = (own_resp or {}).get("body_hash")
                if own_hash and resp.get("body_hash") == own_hash:
                    continue
                is_b = sid in (user_b.known_ids or [])
                candidates.append({
                    "method": method,
                    "path": sub_path,
                    "resource_base": base_url.rstrip("/")
                    + path_tmpl.rsplit("/", 1)[0],
                    "substituted_id": sid,
                    "own_id": own_id,
                    "is_cross_account": is_b,
                    "status": resp.get("status"),
                    "body_hash": resp.get("body_hash"),
                })
    finally:
        client.close()
    return candidates


def _roe_ok(roe_guard, url, method):
    if roe_guard is None:
        return True
    try:
        roe_guard.check_url(url, method)
        return True
    except ROEViolation:
        return False


def compute_differentials(context_sets):
    """Diff crawl sets. Returns list of differential findings."""
    findings = []
    anon = context_sets.get("anon") or {}
    admin = context_sets.get("admin") or {}
    user_a = context_sets.get("user_a") or {}

    # admin ∩ anon reachable -> missing access control
    for key, a_rec in admin.items():
        an_rec = anon.get(key)
        if an_rec and an_rec.get("reachable") and a_rec.get("reachable"):
            findings.append({
                "kind": "missing_access_control",
                "severity": "high",
                "endpoint": key,
                "path": a_rec.get("path"),
                "method": a_rec.get("method"),
                "reason": "sensitive endpoint reachable both by admin and "
                          "anonymously",
            })

    # endpoints in admin crawl but absent/unreachable in user crawl -> PASS
    for key, a_rec in admin.items():
        u_rec = user_a.get(key)
        if a_rec.get("reachable") and (u_rec is None
                                       or not u_rec.get("reachable")):
            if anon.get(key) and anon[key].get("reachable"):
                continue  # already flagged above
            findings.append({
                "kind": "authz_enforced",
                "severity": "info",
                "endpoint": key,
                "path": a_rec.get("path"),
                "method": a_rec.get("method"),
                "reason": "admin-only endpoint correctly denied to lower "
                          "privilege",
            })
    return findings


def scan(base_url, creds=None, creds_path=None, endpoints=None,
         roe_guard=None, fact_store=None, engine_cfg=None, verify=True,
         confirm_fn=None, broker=None):
    """Run the differential crawl and emit facts + IDOR confirmations."""
    if creds is None:
        creds = load_creds(creds_path)
        if creds is None and broker is not None:
            creds = creds_from_broker(broker)
    if roe_guard is None:
        try:
            from .config import load_engine
            roe_guard = ROEGuard(engine_cfg=engine_cfg or load_engine())
        except Exception:
            roe_guard = None
    sessions = build_sessions(creds, verify=verify)
    seed = endpoints or ((creds or {}).get("crawl") or {}).get("endpoints") \
        or []

    context_sets = {}
    for name, session in sessions.items():
        context_sets[name] = crawl_context(base_url, session, seed,
                                            roe_guard=roe_guard, verify=verify)

    diffs = compute_differentials(context_sets)
    idor_candidates = id_substitution_candidates(
        base_url, sessions, seed, roe_guard=roe_guard, verify=verify)

    emitted = []
    for cand in idor_candidates:
        if not cand.get("is_cross_account"):
            continue
        key = f"idor_candidate:{cand['method']}:{cand['path']}"
        if fact_store is not None:
            fact_store.add(key, cand, source="live_confirm", confidence=0.9)
            fact_store.add("has_idor_candidate", True,
                           source="live_confirm", confidence=0.9)
        emitted.append(key)

    for f in diffs:
        if f["kind"] == "missing_access_control" and fact_store is not None:
            fact_store.add(f"access_control:{f['endpoint']}", f,
                           source="live_confirm", confidence=0.9)

    confirmations = []
    if confirm_fn is not None:
        user_a = sessions.get("user_a")
        ctx = {"roe_guard": roe_guard}
        if user_a is not None:
            ctx["headers"] = dict(user_a.headers)
            ctx["cookies"] = dict(user_a.cookies)
        for cand in idor_candidates:
            if not cand.get("is_cross_account"):
                continue
            finding = {"evidence": {
                "resource_base": cand["resource_base"],
                "own_id": cand["own_id"],
                "neighbor_id": cand["substituted_id"],
            }}
            try:
                confirmations.append(
                    {"candidate": cand,
                     "result": confirm_fn("idor_scan", finding, ctx)})
            except Exception as e:
                confirmations.append({"candidate": cand,
                                      "result": {"confirmed": False,
                                                 "reason": str(e)}})

    return {
        "context_sets": {k: list(v.keys()) for k, v in context_sets.items()},
        "differentials": diffs,
        "idor_candidates": idor_candidates,
        "facts_emitted": emitted,
        "confirmations": confirmations,
    }


__all__ = [
    "SessionContext", "load_creds", "creds_from_broker",
    "build_sessions", "crawl_context",
    "compute_differentials", "id_substitution_candidates", "scan",
    "endpoint_key", "ID_SUBST_NEIGHBOR_BOUND", "MAX_REQUESTS_PER_ENDPOINT",
]
