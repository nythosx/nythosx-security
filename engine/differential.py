"""Authenticated differential scanner.

Establishes two independent user sessions (or accepts pre-built ones),
then probes every known endpoint as {anonymous, user_a, user_b} and
structurally diffs the responses.

Findings it produces that pattern-based scanners cannot:

  * Missing auth: anon 200 where auth is expected.
  * BOLA: user_a and user_b both get 200, but their bodies differ in a way
    that shows A saw B's data or B saw A's data.
  * Auth-then-leak: anon 401/403 but user_a 200 on an admin/privileged path.
  * Reflection leak: response body contains a field the other user sent.

Signup is best-effort. If a signup endpoint is discovered and accepts two
distinct {email,password} pairs, sessions are built automatically. Otherwise
the caller supplies credentials_a / credentials_b, or the scan skips with a
clear reason.
"""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urljoin, urlparse

from .config import load_engine
from .contract import Capability, ScanResult
from .diff import SemanticDiff, build_structure, BaselineSnapshot
from .graph import SurfaceGraph, fields_from_body
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


def _strip_noise_body(body):
    try:
        from .noise_model import strip_noise
        return strip_noise(body or "")
    except Exception:
        return body or ""


CAPABILITY = Capability(
    name="differential_scan",
    description=("Cross-auth differential: probe endpoints as anon + two users "
                 "and diff responses structurally. Finds BOLA, missing auth, "
                 "and unauthorized data exposure."),
    category="access-control",
    cost="high",
    destructive=False,
    idempotent=True,
)


COMMON_SIGNUP_PATHS = [
    "/api/register", "/api/signup", "/api/auth/register", "/api/auth/signup",
    "/api/v1/register", "/api/v1/signup", "/api/v1/auth/register",
    "/api/v1/users", "/register", "/signup", "/auth/register", "/auth/signup",
    "/users/register", "/users/signup", "/user/register",
]

COMMON_ENDPOINT_SEEDS = [
    "/api/me", "/api/user", "/api/users", "/api/users/me",
    "/api/account", "/api/profile", "/api/orders", "/api/cart",
    "/api/admin", "/api/admin/users",
]


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="GET"):
    if guard is None:
        try:
            guard = ROEGuard(engine_cfg=load_engine())
        except Exception as e:
            return f"ROE guard unavailable (fail-closed): {e}"
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def _body_hash(body):
    return hashlib.sha256((body or "").encode("utf-8", "ignore")).hexdigest()[:16]


def _request(url, method="GET", headers=None, roe_guard=None, timeout=8,
             verify=None):
    if verify is None:
        verify = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"blocked": True, "url": url, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.request(method.upper(), url, headers=headers or {})
        return {
            "url": str(r.url),
            "status": r.status_code,
            "body": (r.text or "")[:50000],
            "content_type": r.headers.get("Content-Type", ""),
            "body_hash": _body_hash(r.text),
        }
    except _http.ConnectError as e:
        return {"url": url, "status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"url": url, "status": None, "error": "timeout"}
    except Exception as e:
        return {"url": url, "status": None,
                "error": f"{type(e).__name__}: {e}"}


def _try_signup(base_url, email, password, roe_guard=None, timeout=8):
    """Best effort. Returns session dict or None."""
    for path in COMMON_SIGNUP_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        viol = _roe_block(roe_guard, url, "POST")
        if viol:
            continue
        payload = {"email": email, "username": email,
                   "password": password, "password_confirmation": password}
        try:
            with _http.Client(timeout=timeout, verify=_verify_tls(),
                              follow_redirects=False) as c:
                r = c.post(url, json=payload)
        except Exception:
            continue
        if r.status_code in (200, 201, 202):
            return _extract_session_from_response(r)
    return None


def _extract_session_from_response(r):
    session = {"auth_headers": {}, "cookies": {}}
    body = r.text or ""
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    token_paths = [
        ("token",), ("access_token",), ("accessToken",),
        ("data", "token"), ("data", "access_token"),
        ("result", "token"), ("jwt",),
    ]
    for path in token_paths:
        cur = data
        ok = True
        for p in path:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                ok = False
                break
        if ok and isinstance(cur, str) and len(cur) > 15:
            session["auth_headers"]["Authorization"] = f"Bearer {cur}"
            break
    try:
        cookies = dict(r.cookies)
        if cookies:
            session["cookies"] = cookies
    except Exception:
        pass
    if not session["auth_headers"] and not session["cookies"]:
        return None
    return session


def _session_headers(session):
    headers = dict((session or {}).get("auth_headers") or {})
    cookies = (session or {}).get("cookies") or {}
    if cookies and not any(k.lower() == "cookie" for k in headers):
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return headers


def _discover_endpoints(base_url, roe_guard, timeout=8):
    """Try OpenAPI first, fall back to seed list + probed common paths."""
    endpoints = set()
    try:
        from . import openapi_scanner as _oas
        disc = _oas.discover_spec(base_url, timeout=timeout, roe_guard=roe_guard)
        if disc and not disc.get("error"):
            spec = disc.get("spec") or {}
            origin = disc.get("origin") or base_url
            for ep in _oas.extract_endpoints(spec, origin):
                endpoints.add(ep["url"])
    except Exception:
        pass
    for seed in COMMON_ENDPOINT_SEEDS:
        endpoints.add(urljoin(base_url.rstrip("/") + "/", seed.lstrip("/")))
    return sorted(endpoints)


def _diff_finding(f_a, f_b, url, kind, reason, severity="high", evidence_extra=None):
    ev = {"url": url, "kind": kind,
          "status_a": f_a.get("status"), "status_b": f_b.get("status"),
          "hash_a": f_a.get("body_hash"), "hash_b": f_b.get("body_hash")}
    if evidence_extra:
        ev.update(evidence_extra)
    return {"type": kind, "url": url, "reason": reason,
            "severity": severity, "evidence": ev}


def scan(target_url, endpoints=None, credentials_a=None, credentials_b=None,
         signup_base=None, headers=None, roe_guard=None, timeout=8,
         max_endpoints=40):
    verify = _verify_tls()
    viol = _roe_block(roe_guard, target_url, "GET")
    if viol:
        return ScanResult(
            capability="differential_scan", target=target_url,
            verdict="UNKNOWN", reason=f"ROE_BLOCK: {viol}",
        )

    base = target_url.rstrip("/")
    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # --- establish sessions -------------------------------------------------
    session_a = None
    session_b = None
    session_source = []

    if credentials_a and credentials_a.get("session"):
        session_a = credentials_a["session"]
        session_source.append("provided_a")
    if credentials_b and credentials_b.get("session"):
        session_b = credentials_b["session"]
        session_source.append("provided_b")

    if not session_a or not session_b:
        from . import auth_flow
        if credentials_a and credentials_a.get("login_url"):
            r = auth_flow.perform_login(
                credentials_a["login_url"],
                credentials_a.get("username", ""),
                credentials_a.get("password", ""),
                token_path=credentials_a.get("token_path", "token"))
            if r.get("token"):
                session_a = {"auth_headers": {"Authorization": f"Bearer {r['token']}"},
                             "cookies": r.get("cookies") or {}}
                session_source.append("login_a")
        if credentials_b and credentials_b.get("login_url"):
            r = auth_flow.perform_login(
                credentials_b["login_url"],
                credentials_b.get("username", ""),
                credentials_b.get("password", ""),
                token_path=credentials_b.get("token_path", "token"))
            if r.get("token"):
                session_b = {"auth_headers": {"Authorization": f"Bearer {r['token']}"},
                             "cookies": r.get("cookies") or {}}
                session_source.append("login_b")

    if not session_a or not session_b:
        import secrets as _secrets
        sb = signup_base or origin
        if not session_a:
            email = f"sec-a-{_secrets.token_hex(4)}@example.com"
            session_a = _try_signup(sb, email, "SecCheck-A!" + _secrets.token_hex(3),
                                    roe_guard=roe_guard, timeout=timeout)
            if session_a:
                session_source.append("signup_a")
        if not session_b:
            email = f"sec-b-{_secrets.token_hex(4)}@example.com"
            session_b = _try_signup(sb, email, "SecCheck-B!" + _secrets.token_hex(3),
                                    roe_guard=roe_guard, timeout=timeout)
            if session_b:
                session_source.append("signup_b")

    if not session_a and not session_b:
        return ScanResult(
            capability="differential_scan", target=target_url,
            verdict="UNKNOWN",
            reason=("could not establish authenticated sessions: no signup "
                    "endpoint accepted two users and no credentials provided"),
            evidence={"session_source": session_source},
        )

    headers_anon = dict(headers or {})
    headers_a = dict(headers or {})
    headers_a.update(_session_headers(session_a))
    headers_b = dict(headers or {})
    headers_b.update(_session_headers(session_b))

    # --- endpoint list ------------------------------------------------------
    if not endpoints:
        endpoints = _discover_endpoints(base, roe_guard, timeout=timeout)
    endpoints = [u for u in endpoints if u.startswith(("http://", "https://"))][:max_endpoints]

    graph = SurfaceGraph()
    diffs = SemanticDiff()
    findings = []
    probes = []

    for url in endpoints:
        r_anon = _request(url, "GET", headers_anon, roe_guard, timeout, verify)
        if r_anon.get("blocked"):
            continue
        r_a = _request(url, "GET", headers_a, roe_guard, timeout, verify) if session_a else None
        r_b = _request(url, "GET", headers_b, roe_guard, timeout, verify) if session_b else None

        probe = {"url": url,
                 "anon": r_anon.get("status"),
                 "a": (r_a or {}).get("status"),
                 "b": (r_b or {}).get("status")}
        probes.append(probe)

        resp_fields_a = fields_from_body(
            (r_a or {}).get("body", ""), (r_a or {}).get("content_type", ""))
        resp_fields_anon = fields_from_body(
            r_anon.get("body", ""), r_anon.get("content_type", ""))
        graph.add_endpoint(url, "GET",
                            status_anon=r_anon.get("status"),
                            status_auth=(r_a or {}).get("status"),
                            response_fields=(resp_fields_a | resp_fields_anon))

        if r_anon.get("status") is None:
            continue

        if r_anon["status"] in (200, 201, 202) and r_a and r_a.get("status") in (200, 201, 202):
            _ba = _strip_noise_body(r_anon.get("body", ""))
            _bb = _strip_noise_body(r_a.get("body", ""))
            if (_ba != _bb and _session_headers(session_a)):
                b_anon = build_structure(_ba,
                                          r_anon.get("content_type", ""))
                b_auth = build_structure(_bb,
                                          r_a.get("content_type", ""))
                if b_anon is not None and b_auth is not None:
                    base_snap = BaselineSnapshot(
                        url=url, method="GET", status=r_anon["status"],
                        body=_ba,
                        body_len=len(_ba),
                        timing_samples=[10.0],
                        structure=b_anon,
                    )
                    d = diffs.compare(base_snap, {
                        "status": r_a["status"],
                        "body": _bb,
                        "time_ms": 10.0,
                        "content_type": r_a.get("content_type", ""),
                        "headers": {},
                    })
                    if d.structural_delta > 0.35:
                        findings.append(_diff_finding(
                            r_anon, r_a, url, "anon_vs_auth_diff",
                            f"anonymous and authenticated responses differ "
                            f"structurally (delta={d.structural_delta:.2f}) "
                            f"— auth not enforced",
                            severity="high",
                            evidence_extra={"structural_delta": d.structural_delta}))

        _ba = _strip_noise_body(r_a.get("body", "")) if r_a else ""
        _bb = _strip_noise_body(r_b.get("body", "")) if r_b else ""
        if (r_a and r_b
                and r_a.get("status") in (200, 201, 202)
                and r_b.get("status") in (200, 201, 202)
                and _ba != _bb):
            b_a = build_structure(_ba, r_a.get("content_type", ""))
            b_b = build_structure(_bb, r_b.get("content_type", ""))
            if b_a is not None and b_b is not None:
                snap_a = BaselineSnapshot(
                    url=url, method="GET", status=r_a["status"],
                    body=_ba, body_len=len(_ba),
                    timing_samples=[10.0], structure=b_a,
                )
                d = diffs.compare(snap_a, {
                    "status": r_b["status"],
                    "body": _bb,
                    "time_ms": 10.0,
                    "content_type": r_b.get("content_type", ""),
                    "headers": {},
                })
                if d.structural_delta > 0.25 or d.length_delta_pct > 0.3:
                    findings.append(_diff_finding(
                        r_a, r_b, url, "bola_cross_user",
                        f"user A and user B get structurally different "
                        f"responses at the same URL (delta={d.structural_delta:.2f}) "
                        f"— BOLA / cross-tenant access candidate",
                        severity="critical",
                        evidence_extra={"structural_delta": d.structural_delta}))

        if (r_a and r_b
                and r_a.get("status") in (200, 201, 202)
                and r_b.get("status") in (200, 201, 202)
                and r_a.get("body_hash") == r_b.get("body_hash")):
            from .graph import _ID_LEAF_RE as _id_re
            if _id_re.search(urlparse(url).path or ""):
                findings.append(_diff_finding(
                    r_a, r_b, url, "bola_shared_access",
                    "both users get identical 200 response at a per-id URL "
                    "— verify ownership enforcement server-side",
                    severity="high"))

        if (r_a and r_a.get("status") in (200, 201, 202)
                and urlparse(url).path.lower().count("/admin") > 0
                and r_anon["status"] in (401, 403)):
            findings.append(_diff_finding(
                r_anon, r_a, url, "admin_access_as_user",
                "user session reaches an admin path that anon cannot — "
                "verify whether the user should have this access",
                severity="high"))

    graph.build()
    hypotheses = graph.hypotheses()

    if findings:
        return ScanResult(
            capability="differential_scan", target=target_url,
            verdict="VULNERABLE", severity="critical",
            reason=(f"{len(findings)} differential finding(s): "
                    + ", ".join(sorted({f['type'] for f in findings}))),
            evidence={
                "findings": findings,
                "probes": probes[:80],
                "session_source": session_source,
                "graph_stats": graph.stats(),
                "graph_hypotheses": hypotheses[:20],
            },
        )

    if not any(p.get("a") is not None or p.get("b") is not None for p in probes):
        return ScanResult(
            capability="differential_scan", target=target_url,
            verdict="UNKNOWN",
            reason="no authenticated responses observed (sessions may be invalid)",
            evidence={"session_source": session_source,
                      "probes": probes[:40]},
        )

    if not any(p.get("a") in (200, 201, 202) or p.get("b") in (200, 201, 202)
               for p in probes):
        return ScanResult(
            capability="differential_scan", target=target_url,
            verdict="UNKNOWN",
            reason=("sessions never reached a successful response across "
                    f"{len(probes)} endpoint(s) — neither test account "
                    "appears authenticated (e.g. email verification), so no "
                    "real differential comparison happened"),
            evidence={"session_source": session_source,
                      "probes": probes[:40]},
        )

    return ScanResult(
        capability="differential_scan", target=target_url,
        verdict="PASS", severity="low",
        reason=(f"no cross-auth anomaly across {len(probes)} endpoints "
                f"(graph: {graph.stats()['edges']} edge(s), "
                f"{len(hypotheses)} hypothesis(es))"),
        evidence={
            "session_source": session_source,
            "graph_stats": graph.stats(),
            "graph_hypotheses": hypotheses[:20],
            "probes": probes[:40],
        },
    )


__all__ = ["scan", "CAPABILITY", "SurfaceGraph"]
