import pytest


def test_build_context_includes_narrative(monkeypatch, tmp_path):
    from engine import ledger, report
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")
    target = "http://127.0.0.1:9999/api"
    ledger.record_finding(
        pattern_id="jwt-weak-secret", target=target,
        verdict="VULNERABLE", severity="critical",
        reason="hmac cracked", evidence_path="", evidence_json={},
        category="meta",
    )
    ctx = report._build_context(target, engine_cfg={"report": {}})
    assert "narrative_summary" in ctx
    assert isinstance(ctx["narrative_summary"], str)
    assert ctx["narrative_summary"]


def test_template_renders_narrative(monkeypatch, tmp_path):
    from engine import ledger, report
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")
    target = "http://127.0.0.1:9999/api"
    ledger.record_finding(
        pattern_id="jwt-weak-secret", target=target,
        verdict="VULNERABLE", severity="critical",
        reason="hmac cracked", evidence_path="", evidence_json={},
        category="meta",
    )
    path = report.generate(target, fmt="md", engine_cfg={"report": {}})
    import pathlib
    text = pathlib.Path(path).read_text(encoding="utf-8")
    assert "Security Assessment Report" in text
