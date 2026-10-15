"""Drupal / university-CMS chain implementations (Phase 7 Part B)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..roe_guard import ROEViolation

# per-chain request caps
USER_IDOR_MAX = 20
FILE_STORAGE_MAX = 60
STORAGE_ID_WINDOW = 5

_SENSITIVE_NAMES = ["backup", "sql", "config", "credentials", "payroll",
                    "grades"]
_SENSITIVE_EXTS = (".sql", ".bak", ".env", ".xlsx", ".db", ".sqlite")
_MEDIA_EXTS = (".pdf", ".png", ".jpg", ".jpeg", ".gif", ".mp4", ".docx")

_CHANGELOG_VER_RE = re.compile(r"Drupal\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_EMAIL_LOCAL_RE = re.compile(r"[A-Za-z][A-Za-z .'-]+")


# ---- transport -----------------------------------------------------------

def make_send(base_url, client=None, roe_guard=None, headers=None):
    """Build send(method, path, headers=None, params=None) over engine.http."""
    base = base_url.rstrip("/")
    default_headers = dict(headers or {})
    own_client = client is None
    if own_client:
        from .. import http as _http
        client = _http.Client(follow_redirects=False)

    def send(method, path, extra_headers=None, params=None):
        url = path if path.startswith("http") else base + path
        if roe_guard is not None:
            try:
                roe_guard.check_url(url, method)
            except ROEViolation:
                return {"status": None, "body": "", "headers": {},
                        "url": url, "roe_block": True}
        h = dict(default_headers)
        if extra_headers:
            h.update(extra_headers)
        try:
            r = client.request(method, url, headers=h or None, params=params)
        except Exception as e:
            return {"status": None, "body": "", "headers": {}, "url": url,
                    "error": f"{type(e).__name__}: {e}"}
        try:
            body = r.text or ""
        except Exception:
            body = ""
        return {"status": r.status_code, "body": body,
                "headers": dict(getattr(r, "headers", {}) or {}), "url": url}

    send._own_client = own_client
    send._client = client
    return send


def _reachable(resp):
    s = (resp or {}).get("status")
    return s is not None and 200 <= int(s) < 300


# ---- soft-404 fingerprint ------------------------------------------------

@dataclass
class Soft404:
    status: Optional[int] = None
    body_len: int = 0

    def looks_like(self, resp):
        if not _reachable(resp):
            return False
        if self.status is not None and (resp or {}).get("status") == self.status:
            blen = len((resp or {}).get("body") or "")
            if self.body_len and abs(blen - self.body_len) <= max(
                    16, int(self.body_len * 0.05)):
                return True
        return False


def soft404_fingerprint(send, path="/zzz-nonexistent-sentinel-4041x"):
    resp = send("GET", path)
    return Soft404(status=(resp or {}).get("status"),
                   body_len=len((resp or {}).get("body") or ""))


# ---- B1 user IDOR / enumeration ------------------------------------------

def user_idor_chain(send, max_uid=USER_IDOR_MAX, soft404=None):
    findings = []
    requests = 0
    exposed = []
    admin_email = False
    for uid in range(1, max_uid + 1):
        resp = send("GET", f"/user/{uid}")
        requests += 1
        if not _reachable(resp):
            continue
        if soft404 and soft404.looks_like(resp):
            continue
        body = resp.get("body") or ""
        has_name = bool(re.search(r'"name"|username|"display_name"', body))
        has_email = "@" in body and bool(re.search(r'"mail"|"email"', body))
        if has_name or has_email:
            exposed.append({"uid": uid, "email_visible": has_email})
            if uid == 1 and has_email:
                admin_email = True
    if exposed:
        sev = "high" if admin_email else "medium"
        findings.append({
            "type": "user_enumeration", "verdict": "VULNERABLE",
            "severity": sev,
            "reason": f"{len(exposed)} /user/<uid> profile(s) readable "
                      f"anonymously" + (" incl. admin email (uid 1)"
                                        if admin_email else ""),
            "evidence": {"uids": exposed[:20]}})
        # Cross-user private data exposure is object-level access control loss.
        private = [e for e in exposed if e["email_visible"]]
        if private:
            findings.append({
                "type": "idor", "verdict": "VULNERABLE", "severity": "high",
                "reason": f"private profile fields of {len(private)} other "
                          f"user(s) exposed via /user/<uid>",
                "evidence": {"resource_base": "/user",
                             "uids": [e["uid"] for e in private][:10]}})
    return {"findings": findings, "requests": requests}


# ---- B2 REST / JSON:API exposure -----------------------------------------

_REST_ROUTES = [
    "/jsonapi",
    "/jsonapi/node/secret_content",
    "/jsonapi/node/article",
    "/node/1?_format=api_json",
    "/user/register?_format=hal_json",
]


def rest_exposure_chain(send, soft404=None):
    findings = []
    requests = 0
    for route in _REST_ROUTES:
        resp = send("GET", route)
        requests += 1
        if route == "/rest/session/token":
            continue
        if not _reachable(resp):
            continue
        if soft404 and soft404.looks_like(resp):
            continue
        body = resp.get("body") or ""
        is_jsonapi = ('"data"' in body or '"jsonapi"' in body
                      or "_format" in route)
        if is_jsonapi and ("secret" in route or "node" in route):
            findings.append({
                "type": "broken_access_control", "verdict": "VULNERABLE",
                "severity": "high",
                "reason": f"anonymous JSON:API/REST read of {route}",
                "evidence": {"route": route,
                             "preview": body[:200]}})
    # /rest/session/token is expected to be anonymously available in Drupal.
    tok = send("GET", "/rest/session/token")
    requests += 1
    note = None
    if _reachable(tok):
        note = {"type": "rest_session_token", "verdict": "PASS",
                "severity": "info",
                "reason": "/rest/session/token anonymous (expected Drupal "
                          "behaviour) — not flagged"}
    return {"findings": findings, "requests": requests,
            "notes": [note] if note else []}


# ---- B3 views/ajax -------------------------------------------------------

def views_ajax_chain(send, params=None, soft404=None):
    findings = []
    requests = 0
    probes = ["/views/ajax"]
    if params:
        probes.append("/views/ajax?view_name=" + str(params.get(
            "view_name", "content")))
    for path in probes:
        resp = send("GET", path)
        requests += 1
        if not _reachable(resp):
            continue
        if soft404 and soft404.looks_like(resp):
            continue
        body = resp.get("body") or ""
        # Anonymous data dump or missing CSRF token echo.
        dumps_data = ('"data"' in body or "<table" in body.lower()
                      or len(body) > 256)
        if dumps_data:
            findings.append({
                "type": "unauthenticated_data_disclosure",
                "verdict": "VULNERABLE", "severity": "high",
                "reason": f"anonymous data dump from {path} "
                          f"(views/ajax without auth/CSRF)",
                "evidence": {"path": path, "bytes": len(body)}})
    return {"findings": findings, "requests": requests}


# ---- B4 update.php / install.php -----------------------------------------

_MAINT_PATHS = ["/update.php", "/install.php", "/core/install.php",
                "/core/update.php"]


def updatephp_install_chain(send, soft404=None):
    findings = []
    requests = 0
    for path in _MAINT_PATHS:
        resp = send("GET", path)
        requests += 1
        status = (resp or {}).get("status")
        if status == 200 and not (soft404 and soft404.looks_like(resp)):
            findings.append({
                "type": "maintenance_endpoint_exposed", "verdict": "VULNERABLE",
                "severity": "critical",
                "reason": f"{path} returns 200 anonymously (site-takeover "
                          f"path; record-only)",
                "evidence": {"path": path, "status": status},
                "negative_control_path": "/zzz-nonexistent-sentinel-4041x"})
    return {"findings": findings, "requests": requests}


# ---- B5 file storage -----------------------------------------------------

def _is_sensitive_file(path, body):
    low = path.lower()
    if low.endswith(_MEDIA_EXTS):
        return False
    if low.endswith(_SENSITIVE_EXTS):
        return True
    # credential-shaped content heuristic
    if re.search(r"(?i)(password|secret|api[_-]?key|BEGIN [A-Z ]*PRIVATE)",
                 body or ""):
        return True
    return False


def file_storage_chain(send, storage_base="/storage", observed_ids=None,
                       soft404=None, max_requests=FILE_STORAGE_MAX):
    findings = []
    requests = 0
    observed_ids = observed_ids or [113]
    candidate_paths = []
    for oid in observed_ids:
        for i in range(oid - STORAGE_ID_WINDOW, oid + STORAGE_ID_WINDOW + 1):
            if i <= 0:
                continue
            for name in _SENSITIVE_NAMES:
                for ext in (".sql", ".bak", ".env", ".xlsx"):
                    candidate_paths.append(f"{storage_base}/{i}/{name}{ext}")
    seen = set()
    for path in candidate_paths:
        if requests >= max_requests:
            break
        if path in seen:
            continue
        seen.add(path)
        resp = send("GET", path)
        requests += 1
        if not _reachable(resp):
            continue
        if soft404 and soft404.looks_like(resp):
            continue
        body = resp.get("body") or ""
        if _is_sensitive_file(path, body):
            masked = _masked_preview(body)
            findings.append({
                "type": "sensitive_file_exposure", "verdict": "VULNERABLE",
                "severity": "high",
                "reason": f"sensitive file served at {path}",
                "evidence": {"path": path, "masked_preview": masked,
                             "records": [{"path": path, "sample": masked}]}})
    return {"findings": findings, "requests": requests}


def _masked_preview(body):
    try:
        from ..evidence_synth import mask_text_pii
        return mask_text_pii((body or "")[:200])
    except Exception:
        return (body or "")[:80]


# ---- B6 config exposure --------------------------------------------------

_CONFIG_PATHS = ["/sites/default/settings.php", "/core/config.php",
                 "/sites/default/files/.ht.sqlite", "/.env",
                 "/composer.json", "/core/composer.json", "/CHANGELOG.txt"]


def config_exposure_chain(send, soft404=None):
    findings = []
    requests = 0
    version = None
    for path in _CONFIG_PATHS:
        resp = send("GET", path)
        requests += 1
        if not _reachable(resp):
            continue
        if soft404 and soft404.looks_like(resp):
            continue
        body = resp.get("body") or ""
        if path == "/CHANGELOG.txt":
            m = _CHANGELOG_VER_RE.search(body)
            if m:
                version = m.group(1)
                findings.append({
                    "type": "version_disclosure", "verdict": "VULNERABLE",
                    "severity": "info",
                    "reason": f"CHANGELOG.txt discloses Drupal {version}",
                    "evidence": {"version": version}})
        elif path.endswith("settings.php"):
            # settings.php should be 403 via .htaccess; readable = DB creds.
            if re.search(r"(?i)\$databases|'password'|DB_PASSWORD|drupal",
                         body):
                findings.append({
                    "type": "config_disclosure", "verdict": "VULNERABLE",
                    "severity": "critical",
                    "reason": "settings.php readable anonymously (DB "
                              "credentials exposure)",
                    "evidence": {"path": path,
                                 "masked_preview": _masked_preview(body)},
                    "negative_control_path":
                        "/zzz-nonexistent-sentinel-4041x"})
        elif path in ("/.env", "/sites/default/files/.ht.sqlite"):
            findings.append({
                "type": "config_disclosure", "verdict": "VULNERABLE",
                "severity": "high",
                "reason": f"{path} readable anonymously",
                "evidence": {"path": path,
                             "masked_preview": _masked_preview(body)}})
    return {"findings": findings, "requests": requests, "version": version}


# ---- B7 org recon --------------------------------------------------------

def _email_patterns(names):
    patterns = set()
    for full in names:
        parts = [p for p in re.split(r"\s+", full.strip()) if p]
        if len(parts) < 2:
            continue
        first = re.sub(r"[^a-z]", "", parts[0].lower())
        last = re.sub(r"[^a-z]", "", parts[-1].lower())
        if not (first and last):
            continue
        patterns.add(f"{first[0]}.{last}@")
        patterns.add(f"{first}{last}@")
        patterns.add(f"{first}.{last}@")
    return sorted(patterns)


def org_recon_chain(send, path="/administration/key-officials"):
    requests = 0
    resp = send("GET", path)
    requests += 1
    names = []
    if _reachable(resp):
        body = resp.get("body") or ""
        # crude name extraction from list markup
        for m in re.finditer(r">\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s*<",
                             body):
            names.append(m.group(1))
    patterns = _email_patterns(names)
    findings = []
    if patterns:
        findings.append({
            "type": "org_email_patterns", "verdict": "PASS", "severity": "info",
            "reason": f"derived {len(patterns)} candidate email pattern(s) "
                      f"from {len(names)} official name(s) (informational; "
                      f"no email probing performed)",
            "evidence": {"patterns": patterns, "names": names[:20]}})
    return {"findings": findings, "requests": requests,
            "org_email_patterns": patterns}


# ---- orchestration + wiring ----------------------------------------------

def run_all(base_url, client=None, roe_guard=None, fact_store=None,
            gate=None, observed_storage_ids=None, views_params=None):
    """Run B1-B7, route findings through the OracleGate, emit facts.

    Returns {"findings", "facts", "requests", "framework_version",
             "org_email_patterns"}.
    """
    send = make_send(base_url, client=client, roe_guard=roe_guard)
    if gate is None:
        try:
            from ..oracles.controls import OracleGate
            gate = OracleGate(fact_store=fact_store)
        except Exception:
            gate = None
    try:
        soft404 = soft404_fingerprint(send)
    except Exception:
        soft404 = None

    total_requests = 1 if soft404 else 0
    all_findings = []
    version = None
    org_patterns = []

    for name, result in [
        ("user_idor", user_idor_chain(send, soft404=soft404)),
        ("rest", rest_exposure_chain(send, soft404=soft404)),
        ("views", views_ajax_chain(send, params=views_params,
                                   soft404=soft404)),
        ("maintenance", updatephp_install_chain(send, soft404=soft404)),
        ("file_storage", file_storage_chain(
            send, observed_ids=observed_storage_ids, soft404=soft404)),
        ("config", config_exposure_chain(send, soft404=soft404)),
        ("org", org_recon_chain(send)),
    ]:
        total_requests += result.get("requests", 0)
        if name == "config":
            version = result.get("version")
        if name == "org":
            org_patterns = result.get("org_email_patterns", [])
        for f in result.get("findings", []):
            all_findings.append(_apply_gate(f, send, gate))

    confirmed = [f for f in all_findings if f.get("verdict") == "VULNERABLE"]

    facts = {}
    if version:
        facts["framework"] = f"drupal {version}"
        facts["framework_name"] = f"Drupal {version}"
    elif confirmed:
        facts["framework"] = "drupal"
    if org_patterns:
        facts["org_email_patterns"] = org_patterns
    for f in confirmed:
        facts.setdefault("has_" + f["type"], True)

    if fact_store is not None:
        if version:
            fact_store.add("framework", f"drupal {version}",
                           source="active_probe", confidence=0.95)
            fact_store.add("framework_name", f"Drupal {version}",
                           source="active_probe", confidence=0.95)
        elif confirmed:
            fact_store.add("framework", "drupal", source="active_probe",
                           confidence=0.8)
        if org_patterns:
            fact_store.add("org_email_patterns", org_patterns,
                           source="recon", confidence=0.6)
        for f in confirmed:
            fact_store.add("has_" + f["type"], True, source="live_confirm",
                           confidence=0.9)

    if getattr(send, "_own_client", False):
        try:
            send._client.close()
        except Exception:
            pass

    return {"findings": all_findings, "confirmed": confirmed, "facts": facts,
            "requests": total_requests, "framework_version": version,
            "org_email_patterns": org_patterns}


def _apply_gate(finding, send, gate):
    """Route a finding through the negative-control gate where declared.

    B4/B6 use a benign-path 404 control: if the benign nonexistent path also
    'fires' (returns 200 / sensitive), the detector is unsound -> suppress.
    """
    if gate is None:
        return finding
    nc_path = finding.get("negative_control_path")
    if not nc_path:
        return finding

    def probe(payload):
        resp = send("GET", payload)
        # The detector 'fires' if a benign nonexistent path looks reachable.
        if _reachable(resp):
            return {"verdict": "VULNERABLE"}
        return {"verdict": "PASS"}

    from ..oracles.controls import negative_control
    oracle = finding.get("type", "")
    control = probe(nc_path)
    if control.get("verdict") == "VULNERABLE":
        finding = dict(finding)
        finding["verdict"] = "PASS"
        finding["reason"] = ("[suppressed: benign-path control reachable] "
                             + finding.get("reason", ""))
        finding["confirmation_status"] = "tool_unsound"
    else:
        finding = dict(finding)
        finding["confirmation_status"] = "confirmed"
    return finding


__all__ = [
    "make_send", "soft404_fingerprint", "Soft404", "run_all",
    "user_idor_chain", "rest_exposure_chain", "views_ajax_chain",
    "updatephp_install_chain", "file_storage_chain", "config_exposure_chain",
    "org_recon_chain", "USER_IDOR_MAX", "FILE_STORAGE_MAX",
]
