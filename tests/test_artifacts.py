import pytest


def test_roundtrip_plaintext(monkeypatch, tmp_path):
    monkeypatch.delenv("EVIDENCE_KEY", raising=False)
    from engine import artifacts
    monkeypatch.setattr(artifacts, "ARTIFACT_DIR", tmp_path)
    target = "example.test"
    artifacts.write(target, "jwt_secret", {"secret": "abc"},
                    chain_id="c1", outcome="SESSION_MATERIAL")
    artifacts.write(target, "ssrf_meta", {"role": "arn:aws:iam::1:role/x"},
                    chain_id="c2")
    entries = artifacts.load_for(target)
    assert len(entries) == 2
    assert entries[0]["kind"] == "jwt_secret"
    assert entries[0]["value"]["secret"] == "abc"
    assert entries[0]["outcome"] == "SESSION_MATERIAL"
    assert entries[1]["kind"] == "ssrf_meta"


def test_isolated_per_target(monkeypatch, tmp_path):
    monkeypatch.delenv("EVIDENCE_KEY", raising=False)
    from engine import artifacts
    monkeypatch.setattr(artifacts, "ARTIFACT_DIR", tmp_path)
    artifacts.write("a.test", "k", {"v": 1})
    artifacts.write("b.test", "k", {"v": 2})
    assert len(artifacts.load_for("a.test")) == 1
    assert len(artifacts.load_for("b.test")) == 1
    assert artifacts.load_for("a.test")[0]["value"]["v"] == 1


def test_empty_target_safe(monkeypatch, tmp_path):
    from engine import artifacts
    monkeypatch.setattr(artifacts, "ARTIFACT_DIR", tmp_path)
    assert artifacts.write("", "k", {}) is None
    assert artifacts.load_for("") == []


def test_clear(monkeypatch, tmp_path):
    monkeypatch.delenv("EVIDENCE_KEY", raising=False)
    from engine import artifacts
    monkeypatch.setattr(artifacts, "ARTIFACT_DIR", tmp_path)
    artifacts.write("t.test", "k", {"v": 1})
    assert len(artifacts.load_for("t.test")) == 1
    artifacts.clear("t.test")
    assert artifacts.load_for("t.test") == []


def test_encrypted_roundtrip(monkeypatch, tmp_path):
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("EVIDENCE_KEY", key)
    from engine import artifacts
    monkeypatch.setattr(artifacts, "ARTIFACT_DIR", tmp_path)
    artifacts.write("e.test", "k", {"v": "sensitive"})
    entries = artifacts.load_for("e.test")
    assert len(entries) == 1
    assert entries[0]["value"]["v"] == "sensitive"
    enc = tmp_path / (artifacts._safe("e.test") + ".jsonl.enc")
    assert enc.exists()


def test_corrupt_line_skipped(monkeypatch, tmp_path):
    monkeypatch.delenv("EVIDENCE_KEY", raising=False)
    from engine import artifacts
    monkeypatch.setattr(artifacts, "ARTIFACT_DIR", tmp_path)
    artifacts.write("c.test", "k", {"v": 1})
    p = tmp_path / (artifacts._safe("c.test") + ".jsonl")
    with p.open("a", encoding="utf-8") as fh:
        fh.write("not-json\n")
    entries = artifacts.load_for("c.test")
    assert len(entries) == 1
