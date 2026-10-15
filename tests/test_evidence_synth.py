import json
import re

import pytest

from engine import evidence_synth as es


# ---- masking -------------------------------------------------------------

def test_mask_email():
    assert es.mask_email("alice@example.com") == "a•••@•••.com"


def test_mask_digits_keeps_last_two():
    out = es.mask_digits("4111111111111234")
    assert out.endswith("34")
    assert out.count("•") == len("4111111111111234") - 2


def test_mask_value_dispatch():
    assert "@" in es.mask_value("bob@example.com")
    assert es.mask_value("4222222222225678").endswith("78")


def test_mask_text_pii_masks_credentials():
    assert "S3cr3t" not in es.mask_text_pii("SET PASSWORD = 'S3cr3tDbP@ss';")
    assert "hunter2" not in es.mask_text_pii("'password' => 'hunter2',")
    assert "AKIA" not in es.mask_text_pii("api_key: AKIAABCDEF12TOKEN")


def test_mask_record_nested_and_secrets():
    rec = {"email": "x@y.com", "account": "4111111111111234",
           "password": "hunter2", "nested": {"token": "abc"}}
    masked = es.mask_record(rec)
    assert masked["password"] == "<REDACTED>"
    assert masked["nested"]["token"] == "<REDACTED>"
    assert "x@y.com" not in json.dumps(masked)
    assert "4111111111111234" not in json.dumps(masked)


# ---- remediation ---------------------------------------------------------

def test_remediation_known_class():
    assert "authorization" in es.remediation_for("idor").lower()


def test_remediation_prefix_match():
    assert es.remediation_for("stored-xss")


def test_remediation_unknown_fallback():
    assert es.remediation_for("made-up-thing")


# ---- curl + raw ----------------------------------------------------------

def test_curl_redacts_auth_header():
    curl = es.curl_oneliner("GET", "http://t/x",
                            headers={"Authorization": "Bearer secrettoken123456"},
                            body=None)
    assert "secrettoken" not in curl
    assert "<REDACTED>" in curl


def test_raw_pair_truncates_body():
    big = "A" * (es.BODY_TRUNCATE + 500)
    _, resp = es.raw_pair({"method": "GET", "url": "/x"},
                          {"status": 200, "body": big})
    assert "truncated" in resp
    assert len(resp) < len(big)


# ---- encrypted store -----------------------------------------------------

def test_encrypted_store_roundtrip(tmp_path):
    key = es.generate_key()
    store = es.EncryptedEvidenceStore(key=key, store_dir=tmp_path)
    assert store.available
    path = store.store("finding_1", {"records": [{"email": "a@b.com"}]})
    assert path
    # ciphertext on disk does not contain the plaintext
    raw = (tmp_path / "finding_1.enc").read_bytes()
    assert b"a@b.com" not in raw
    loaded = json.loads(store.load("finding_1"))
    assert loaded["records"][0]["email"] == "a@b.com"


def test_store_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("EVIDENCE_KEY", raising=False)
    store = es.EncryptedEvidenceStore()
    assert not store.available
    assert store.store("f", {"x": 1}) is None


# ---- 3-row block ---------------------------------------------------------

def test_build_evidence_block_three_rows():
    finding = {"id": "f1", "finding_class": "idor",
               "reason": "neighbor record read",
               "evidence": {"records": [
                   {"email": "alice@example.com", "account": "4111111111111234"},
                   {"email": "bob@example.com", "account": "4222222222225678"}]}}
    response = {"status": 200,
                "body": json.dumps(finding["evidence"]["records"]),
                "content_type": "application/json"}
    request = {"method": "GET", "url": "http://t/api/doc/2"}
    block = es.build_evidence_block(finding, request=request,
                                    response=response)
    assert set(block) == {"reproduction", "impact", "differential"}
    assert block["impact"]["record_count"] == 2
    assert len(block["impact"]["response_sha256"]) == 64
    assert block["differential"]["remediation"]


def test_verify_fix_signed_record():
    rec = es.verify_fix("f1", lambda: {"verdict": "PASS", "reason": "ok"})
    assert rec["verdict"] == "fixed & verified"
    assert len(rec["signature"]) == 64
    rec2 = es.verify_fix("f2", lambda: {"verdict": "VULNERABLE"})
    assert rec2["verdict"] == "still vulnerable"


# ---- end-to-end: report from the local test app, no data leaks -----------

_FULL_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_LONG_DIGITS_RE = re.compile(r"\d{5,}")


def test_e2e_report_masks_all_third_party_data(tmp_path, monkeypatch):
    from engine import http as _http
    from tests.testapp import start_app

    base, srv = start_app()
    try:
        client = _http.Client(follow_redirects=False)
        try:
            # user_b's record contains a real email + account number
            r = client.get(base + "/api/doc/2",
                           headers={"Authorization": "Bearer tok-user-a"})
            body = r.text
        finally:
            client.close()
        assert _FULL_EMAIL_RE.search(body), "fixture should contain an email"

        records = [json.loads(body)]
        finding = {"id": "e2e", "finding_class": "idor",
                   "reason": "cross-account record read",
                   "evidence": {"records": records}}
        response = {"status": 200, "body": body,
                    "content_type": "application/json"}
        request = {"method": "GET", "url": base + "/api/doc/2",
                   "headers": {"Authorization": "Bearer tok-user-a"}}
        block = es.build_evidence_block(finding, request=request,
                                        response=response)
        report_md = es.render_markdown(block, finding)
        report_file = tmp_path / "report.md"
        report_file.write_text(report_md, encoding="utf-8")

        text = report_file.read_text(encoding="utf-8")
        # all 3 rows present
        assert "Row 1 — Reproduction" in text
        assert "Row 2 — Impact" in text
        assert "Row 3 — Differential" in text
        # the specific third-party values must never appear verbatim
        assert "bob@example.com" not in text
        assert "4222222222225678" not in text
        # no full email leaks (emails never appear in URLs/hashes)
        assert not _FULL_EMAIL_RE.search(text), "email leaked into report"
        # no long digit run leaks, ignoring the ephemeral port and the sha
        scrubbed = text.replace(base, "").replace(
            block["impact"]["response_sha256"], "")
        assert not _LONG_DIGITS_RE.search(scrubbed), \
            "account number leaked into report"
    finally:
        srv.shutdown()
