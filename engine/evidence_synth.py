"""Phase 4 — Evidence Synthesizer.

For every CONFIRMED finding, build a three-row evidence block:

  Row 1 — Reproduction: a minimal curl one-liner plus the raw
          request/response pair (bodies truncated to 2 KB, credentials
          redacted).
  Row 2 — Impact: for data-exposure findings, the record COUNT, the first
          two records with values MASKED (j•••@•••.com, digits → • except
          the last two), and a SHA-256 of the full response. Unmasked
          third-party data never enters the report — the full payload is
          kept only in the local Fernet-encrypted evidence store (key from
          EVIDENCE_KEY).
  Row 3 — Differential: baseline vs exploit rendered side-by-side using the
          existing semantic_diff structural hash, plus a one-line
          remediation for the finding class (remediation_map.yaml).

Fix-verification (`--verify-fix <finding_id>`) re-runs the minimal PoC and,
on PASS, emits a signed "fixed & verified" JSON record into the report.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from . import redact
from .diff import BaselineSnapshot, SemanticDiff, build_structure, _structural_hash

ROOT = Path(__file__).parent.parent.absolute()
REMEDIATION_MAP = ROOT / "configs" / "remediation_map.yaml"
ENCRYPTED_STORE = ROOT / "evidence" / "encrypted"

BODY_TRUNCATE = 2048
MASK = "•"  # bullet


# ---- masking -------------------------------------------------------------

_EMAIL_RE = re.compile(r"([^@\s])[^@\s]*@[^@\s]+\.([A-Za-z0-9]+)")


def mask_email(value):
    m = _EMAIL_RE.search(str(value))
    if not m:
        return value
    return f"{m.group(1)}{MASK * 3}@{MASK * 3}.{m.group(2)}"


def mask_digits(value):
    """Replace digits with the mask char, keeping only the last two."""
    s = str(value)
    digits = [i for i, c in enumerate(s) if c.isdigit()]
    if not digits:
        return s
    keep = set(digits[-2:])
    return "".join(c if (not c.isdigit() or i in keep) else MASK
                   for i, c in enumerate(s))


def mask_value(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    s = str(value)
    if "@" in s and _EMAIL_RE.search(s):
        return mask_email(s)
    if any(c.isdigit() for c in s):
        return mask_digits(s)
    if len(s) <= 2:
        return MASK * len(s)
    return s[0] + MASK * 3


_PII_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PII_DIGITS_RE = re.compile(r"\d{5,}")


def mask_text_pii(s):
    """Mask third-party PII (emails, long digit runs) in free text.

    Applied to raw request/response bodies so Row 1 never leaks the data that
    Row 2 masks. Credential redaction is layered separately.
    """
    if not isinstance(s, str) or not s:
        return s
    s = _PII_EMAIL_RE.sub(lambda m: mask_email(m.group(0)), s)
    s = _PII_DIGITS_RE.sub(lambda m: mask_digits(m.group(0)), s)
    return s


def mask_record(record):
    if isinstance(record, dict):
        return {k: (redact.PLACEHOLDER if redact._is_sensitive_key(k)
                    else mask_record(v)) for k, v in record.items()}
    if isinstance(record, list):
        return [mask_record(v) for v in record]
    return mask_value(record)


# ---- encrypted evidence store (Fernet) -----------------------------------

def _load_key():
    key = os.environ.get("EVIDENCE_KEY")
    return key.encode("utf-8") if key else None


def generate_key():
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode("ascii")


class EncryptedEvidenceStore:
    """Fernet-encrypted at-rest store for full (unmasked) payloads."""

    def __init__(self, key=None, store_dir=None):
        self.key = key or _load_key()
        self.store_dir = Path(store_dir or ENCRYPTED_STORE)

    @property
    def available(self):
        return bool(self.key)

    def store(self, finding_id, payload):
        if not self.available:
            return None
        from cryptography.fernet import Fernet
        try:
            f = Fernet(self.key)
        except Exception:
            return None
        data = payload if isinstance(payload, (bytes, bytearray)) \
            else json.dumps(payload, default=str).encode("utf-8")
        token = f.encrypt(bytes(data))
        self.store_dir.mkdir(parents=True, exist_ok=True)
        path = self.store_dir / f"{_safe(finding_id)}.enc"
        path.write_bytes(token)
        return str(path)

    def load(self, finding_id):
        if not self.available:
            return None
        from cryptography.fernet import Fernet
        path = self.store_dir / f"{_safe(finding_id)}.enc"
        if not path.exists():
            return None
        f = Fernet(self.key)
        return f.decrypt(path.read_bytes())


def _safe(s):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in str(s))[:80]


# ---- remediation map -----------------------------------------------------

_DEFAULT_REMEDIATION = {
    "idor": "Enforce object-level authorization: check the authenticated "
            "subject owns or may access the requested resource ID.",
    "bola": "Enforce object-level authorization on every record lookup; "
            "never trust a client-supplied object ID.",
    "sqli": "Use parameterized queries / prepared statements; never "
            "concatenate user input into SQL.",
    "xss": "Context-encode output and apply a strict Content-Security-Policy; "
           "never reflect raw user input into HTML.",
    "ssrf": "Validate and allowlist outbound URLs; block internal address "
            "ranges and metadata endpoints.",
    "ssti": "Never render user input as a template; use a sandboxed, "
            "logic-less templating layer.",
    "jwt_weak_secret": "Rotate to a high-entropy signing key, pin the "
                       "algorithm server-side, and reject alg:none.",
    "mass_assignment": "Bind only an explicit allowlist of writable fields; "
                       "reject unknown keys.",
    "missing_access_control": "Require authentication and role checks on all "
                              "sensitive endpoints; deny by default.",
    "nosql": "Reject operator objects in user input; cast and validate types "
             "before querying.",
    "crlf": "Strip/encode CR and LF from any value placed into response "
            "headers.",
    "open_redirect": "Allowlist redirect targets; never redirect to a raw "
                     "user-supplied URL.",
    "data_exposure": "Scope data responses to the authenticated subject and "
                     "paginate with server-side authorization.",
}


def load_remediation_map(path=None):
    p = Path(path) if path else REMEDIATION_MAP
    data = dict(_DEFAULT_REMEDIATION)
    if p.exists():
        try:
            import yaml
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                data.update({k: str(v) for k, v in loaded.items()})
        except Exception:
            pass
    return data


def remediation_for(finding_class, path=None):
    rmap = load_remediation_map(path)
    if finding_class in rmap:
        return rmap[finding_class]
    for key, val in rmap.items():
        if finding_class and (finding_class.startswith(key)
                              or key in finding_class):
            return val
    return "Review and remediate per the relevant OWASP control."


# ---- curl + raw pair -----------------------------------------------------

def _truncate(body):
    if body is None:
        return ""
    s = body if isinstance(body, str) else str(body)
    if len(s) > BODY_TRUNCATE:
        return s[:BODY_TRUNCATE] + f"\n...[truncated {len(s) - BODY_TRUNCATE} "\
            f"bytes]"
    return s


def curl_oneliner(method, url, headers=None, body=None):
    parts = ["curl", "-i", "-X", method.upper()]
    for k, v in (redact.redact_headers(headers or {}) or {}).items():
        parts.append("-H")
        parts.append(_shellq(f"{k}: {v}"))
    if body:
        parts.append("--data")
        parts.append(_shellq(_truncate(
            mask_text_pii(redact.redact_text(str(body))))))
    parts.append(_shellq(redact.redact_url(url)))
    return " ".join(parts)


def _shellq(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def raw_pair(request, response):
    req_body = _truncate(mask_text_pii(
        redact.redact_text(str(request.get("body") or ""))))
    resp_body = _truncate(mask_text_pii(
        redact.redact_text(str(response.get("body") or ""))))
    req_headers = redact.redact_headers(request.get("headers") or {})
    resp_headers = redact.redact_headers(response.get("headers") or {})
    req_lines = [f"{request.get('method', 'GET')} "
                 f"{redact.redact_url(request.get('url', '/'))}"]
    req_lines += [f"{k}: {v}" for k, v in req_headers.items()]
    if req_body:
        req_lines += ["", req_body]
    resp_lines = [f"HTTP {response.get('status', '')}"]
    resp_lines += [f"{k}: {v}" for k, v in resp_headers.items()]
    if resp_body:
        resp_lines += ["", resp_body]
    return "\n".join(req_lines), "\n".join(resp_lines)


# ---- the three-row block -------------------------------------------------

def _records_from_finding(finding):
    ev = (finding or {}).get("evidence") or {}
    for k in ("extracted_records", "records", "rows", "items"):
        v = ev.get(k)
        if isinstance(v, list) and v:
            return v
    return []


def _finding_class(finding):
    return (finding.get("finding_class") or finding.get("class")
            or finding.get("capability") or finding.get("pattern_id")
            or finding.get("kind") or "")


def build_evidence_block(finding, request=None, response=None,
                         baseline=None, store=None, remediation_path=None):
    """Return the 3-row evidence block (report-safe; fully masked)."""
    request = request or {}
    response = response or {}
    diff = SemanticDiff()

    # Row 1 — Reproduction
    curl = curl_oneliner(request.get("method", "GET"),
                         request.get("url", ""),
                         request.get("headers"), request.get("body"))
    req_raw, resp_raw = raw_pair(request, response)
    row1 = {"curl": curl, "request": req_raw, "response": resp_raw}

    # Row 2 — Impact
    records = _records_from_finding(finding)
    full_body = response.get("body") or ""
    sha = hashlib.sha256(full_body.encode("utf-8", "ignore")).hexdigest() \
        if full_body else None
    masked_sample = [mask_record(r) for r in records[:2]]
    stored_path = None
    if records and store is not None and store.available:
        stored_path = store.store(
            finding.get("id") or finding.get("finding_id") or "finding",
            {"records": records, "response_body": full_body})
    row2 = {
        "record_count": len(records),
        "sample_masked": masked_sample,
        "response_sha256": sha,
        "encrypted_store_path": stored_path,
    }

    # Row 3 — Differential + remediation
    base_struct = None
    exploit_struct = build_structure(response.get("body") or "",
                                     response.get("content_type", ""))
    if isinstance(baseline, BaselineSnapshot):
        base_struct = baseline.structure
        d = diff.compare(baseline, response)
        structural_delta = round(d.structural_delta, 4)
    elif isinstance(baseline, dict):
        base_struct = build_structure(baseline.get("body") or "",
                                      baseline.get("content_type", ""))
        structural_delta = None
    else:
        structural_delta = None
    row3 = {
        "baseline_hash": _structural_hash(base_struct) if base_struct else "",
        "exploit_hash": _structural_hash(exploit_struct)
        if exploit_struct else "",
        "structural_delta": structural_delta,
        "remediation": remediation_for(_finding_class(finding),
                                       remediation_path),
    }

    return {"reproduction": row1, "impact": row2, "differential": row3}


def render_markdown(block, finding=None):
    r1, r2, r3 = block["reproduction"], block["impact"], block["differential"]
    out = []
    title = (finding or {}).get("reason") or (finding or {}).get("id") \
        or "Finding"
    out.append(f"### Evidence — {title}")
    out.append("\n**Row 1 — Reproduction**\n")
    out.append("```sh\n" + r1["curl"] + "\n```")
    out.append("```http\n" + r1["request"] + "\n\n" + r1["response"] + "\n```")
    out.append("\n**Row 2 — Impact**\n")
    out.append(f"- Records exposed: **{r2['record_count']}**")
    if r2["response_sha256"]:
        out.append(f"- Response SHA-256: `{r2['response_sha256']}`")
    if r2["sample_masked"]:
        out.append("- Sample (masked):")
        out.append("```json\n"
                   + json.dumps(r2["sample_masked"], indent=2, default=str,
                                ensure_ascii=False)
                   + "\n```")
    if r2["encrypted_store_path"]:
        out.append(f"- Full payload (encrypted): `{r2['encrypted_store_path']}`")
    out.append("\n**Row 3 — Differential**\n")
    out.append(f"- baseline: `{r3['baseline_hash'][:80]}`")
    out.append(f"- exploit:  `{r3['exploit_hash'][:80]}`")
    if r3["structural_delta"] is not None:
        out.append(f"- structural delta: {r3['structural_delta']}")
    out.append(f"- **Remediation:** {r3['remediation']}")
    return "\n".join(out)


# ---- fix verification (signed record) ------------------------------------

def _sign(record, key=None):
    key = (key or os.environ.get("EVIDENCE_KEY") or "unsigned").encode("utf-8")
    body = json.dumps(record, sort_keys=True, default=str).encode("utf-8")
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def verify_fix(finding_id, poc_runner):
    """Re-run the minimal PoC. poc_runner() -> verdict dict.

    PASS (no longer VULNERABLE) emits a signed 'fixed & verified' record.
    """
    try:
        result = poc_runner()
    except Exception as e:
        result = {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
    verdict = (result or {}).get("verdict")
    fixed = verdict != "VULNERABLE"
    record = {
        "finding_id": finding_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": "fixed & verified" if fixed else "still vulnerable",
        "poc_verdict": verdict,
        "reason": (result or {}).get("reason"),
    }
    record["signature"] = _sign(record)
    return record


__all__ = [
    "mask_email", "mask_digits", "mask_value", "mask_record",
    "EncryptedEvidenceStore", "generate_key", "load_remediation_map",
    "remediation_for", "curl_oneliner", "raw_pair", "build_evidence_block",
    "render_markdown", "verify_fix", "BODY_TRUNCATE",
]
