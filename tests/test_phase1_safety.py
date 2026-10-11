"""Phase 1 tests: redaction, strict YAML, schema, version, examples."""
import json
from pathlib import Path

import pytest


# ---------- version ----------
def test_version_module_exists():
    from engine import version
    assert isinstance(version.__version__, str)
    assert version.__version__


def test_report_version_matches():
    from engine import report
    from engine.version import __version__
    assert report.SEC_CHECKER_VERSION == __version__


def test_sbom_version_matches():
    from engine import sbom
    from engine.version import __version__
    assert sbom.SEC_CHECKER_VERSION == __version__


# ---------- redaction ----------
def test_redact_bearer():
    from engine import redact
    out = redact.redact_text("Authorization: Bearer abcdefghijklmnop1234567890")
    assert "abcdefghijklmnop1234567890" not in out
    assert "<REDACTED>" in out


def test_redact_jwt():
    from engine import redact
    jwt = ("eyJhbGciOiJIUzI1NiJ9"
           ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
           ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
    out = redact.redact_text(f"token={jwt}")
    assert jwt not in out


def test_redact_aws_key():
    from engine import redact
    out = redact.redact_text("AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_redact_private_key():
    from engine import redact
    text = ("-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA...\n"
            "-----END RSA PRIVATE KEY-----")
    out = redact.redact_text(text)
    assert "MIIEowIBAAKCAQEA" not in out


def test_redact_headers():
    from engine import redact
    h = {"Authorization": "Bearer xyz",
         "Content-Type": "application/json"}
    out = redact.redact_headers(h)
    assert out["Authorization"] == "<REDACTED>"
    assert out["Content-Type"] == "application/json"


def test_redact_dict_recurses():
    from engine import redact
    d = {"a": {"b": "AKIAIOSFODNN7EXAMPLE"},
         "c": ["Bearer secret-token-abcdefghij"]}
    out = redact.redact_dict(d)
    dumped = json.dumps(out)
    assert "AKIAIOSFODNN7EXAMPLE" not in dumped
    assert "secret-token-abcdefghij" not in dumped


def test_redact_sensitive_key_exact():
    from engine import redact
    out = redact.redact_dict({"password": "hunter2"})
    assert out["password"] == "<REDACTED>"


def test_redact_sensitive_key_suffix():
    from engine import redact
    out = redact.redact_dict({"refresh_token": "abc123"})
    assert out["refresh_token"] == "<REDACTED>"


def test_redact_non_sensitive_key_preserved():
    from engine import redact
    out = redact.redact_dict({"username": "alice"})
    assert out["username"] == "alice"


def test_redact_idempotent():
    from engine import redact
    s = "AKIAIOSFODNN7EXAMPLE and Bearer abcdefghij1234567890"
    once = redact.redact_text(s)
    twice = redact.redact_text(once)
    assert once == twice


# ---------- strict YAML ----------
def test_strict_yaml_rejects_duplicates():
    import yaml
    from engine.util import strict_yaml_load
    with pytest.raises(yaml.YAMLError):
        strict_yaml_load("a: 1\na: 2\n")


def test_strict_yaml_accepts_clean():
    from engine.util import strict_yaml_load
    data = strict_yaml_load("a: 1\nb: [1, 2]\n")
    assert data == {"a": 1, "b": [1, 2]}


def test_strict_yaml_handles_empty():
    from engine.util import strict_yaml_load
    assert strict_yaml_load("") is None


# ---------- schema ----------
def test_validate_pattern_ok():
    from engine import schema
    data = {"id": "x", "name": "X", "severity": "high",
            "steps": [], "oracles": []}
    assert schema.validate_pattern(data)


def test_validate_pattern_missing_id():
    from engine import schema
    with pytest.raises(schema.SchemaError):
        schema.validate_pattern({"name": "X", "severity": "high",
                                  "steps": [], "oracles": []})


def test_validate_pattern_bad_severity():
    from engine import schema
    with pytest.raises(schema.SchemaError):
        schema.validate_pattern({"id": "x", "name": "X",
                                  "severity": "SUPER",
                                  "steps": [], "oracles": []})


def test_validate_adapter_ok():
    from engine import schema
    assert schema.validate_adapter({"id": "express", "name": "Express",
                                    "detect": {}})


def test_validate_chain_ok():
    from engine import schema
    data = {"id": "c", "name": "C",
            "trigger": {"mode": "any",
                        "conditions": [{"fact": "x"}]},
            "steps": [{"id": "s", "tool": "t"}]}
    assert schema.validate_chain(data)


def test_validate_chain_missing_trigger():
    from engine import schema
    with pytest.raises(schema.SchemaError):
        schema.validate_chain({"id": "c", "name": "C", "steps": []})


# ---------- config strict load ----------
def test_load_engine_strict_rejects_dupes(monkeypatch, tmp_path):
    from engine import config as cfg
    monkeypatch.setattr(cfg, "CONFIGS", tmp_path)
    (tmp_path / "engine.yaml").write_text("http: {}\nhttp: {}\n")
    with pytest.raises(RuntimeError):
        cfg.load_engine()


def test_load_engine_ok(monkeypatch, tmp_path):
    from engine import config as cfg
    monkeypatch.setattr(cfg, "CONFIGS", tmp_path)
    (tmp_path / "engine.yaml").write_text("http:\n  timeout_seconds: 5\n")
    data = cfg.load_engine()
    assert data["http"]["timeout_seconds"] == 5


def test_load_engine_merges_defaults(monkeypatch, tmp_path):
    from engine import config as cfg
    monkeypatch.setattr(cfg, "CONFIGS", tmp_path)
    (tmp_path / "engine.yaml").write_text("http:\n  timeout_seconds: 5\n")
    data = cfg.load_engine()
    assert "budget" in data
    assert "redaction" in data
    assert "oob" in data


def test_load_roe_ok(monkeypatch, tmp_path):
    from engine import config as cfg
    monkeypatch.setattr(cfg, "CONFIGS", tmp_path)
    (tmp_path / "roe.yaml").write_text(
        "enabled: true\nscope:\n  in_scope: [localhost]\n")
    data = cfg.load_roe()
    assert data["enabled"] is True


def test_load_roe_rejects_bad_scope_type(monkeypatch, tmp_path):
    from engine import config as cfg
    monkeypatch.setattr(cfg, "CONFIGS", tmp_path)
    (tmp_path / "roe.yaml").write_text(
        "enabled: true\nscope: not-a-mapping\n")
    with pytest.raises(RuntimeError):
        cfg.load_roe()


def test_load_targets_ok(monkeypatch, tmp_path):
    from engine import config as cfg
    monkeypatch.setattr(cfg, "CONFIGS", tmp_path)
    (tmp_path / "targets.yaml").write_text(
        "targets:\n  t1:\n    url: http://x\n")
    data = cfg.load_targets()
    assert "t1" in data["targets"]


def test_load_credentials_ok(monkeypatch, tmp_path):
    from engine import config as cfg
    monkeypatch.setattr(cfg, "CONFIGS", tmp_path)
    (tmp_path / "credentials.yaml").write_text(
        "credentials:\n  localhost:\n    username: a\n")
    data = cfg.load_credentials()
    assert "localhost" in data["credentials"]


# ---------- example configs parse ----------
def test_example_configs_parse():
    from engine.util import strict_yaml_load
    root = Path(__file__).resolve().parent.parent
    cfg_dir = root / "configs"
    for name in ("engine.example.yaml", "roe.example.yaml",
                 "targets.example.yaml", "credentials.example.yaml"):
        p = cfg_dir / name
        if not p.exists():
            pytest.skip(f"missing {name}")
        strict_yaml_load(p.read_text(encoding="utf-8"))


# ---------- evidence + ledger redaction ----------
def test_evidence_redacts_headers(tmp_path, monkeypatch):
    from engine import evidence
    monkeypatch.setattr(evidence, "EVIDENCE_DIR", tmp_path)
    ctx = {
        "steps": [{
            "step_name": "s", "loop_index": 0, "status": 200,
            "time_ms": 1.0, "body_hash": "h", "url": "http://t",
            "error": None,
            "headers": {"Authorization": "Bearer abcdef1234567890xyz"},
            "body": "ok",
        }],
        "inputs": {}, "target": "http://t",
    }
    cfg = {"evidence": {"save_raw_bodies": True, "max_body_size_kb": 100}}
    path = evidence.save_evidence(
        "p", "http://t", ctx, "PASS",
        {"reason": "", "evidence": {}}, engine_cfg=cfg)
    raw = json.loads((Path(path) / "raw.json").read_text())
    auth = raw[0]["headers"].get("Authorization")
    assert auth == "<REDACTED>"


def test_ledger_redacts_reason(tmp_path, monkeypatch):
    from engine import ledger
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    secret = "AKIAIOSFODNN7EXAMPLE"
    ledger.record_finding(
        "p", "http://t", "VULNERABLE", "high",
        f"leaked {secret}", "", {})
    rows = ledger.recent_findings(limit=1)
    assert secret not in (rows[0][6] or "")


def test_ledger_redacts_evidence_json(tmp_path, monkeypatch):
    from engine import ledger
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    ledger.record_finding(
        "p", "http://t", "VULNERABLE", "high", "x", "",
        {"token": "abcdef1234567890abcdef"})
    conn = ledger._connect()
    row = conn.execute(
        "SELECT evidence_json FROM findings ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert "abcdef1234567890abcdef" not in (row[0] or "")
