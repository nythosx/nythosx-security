"""Phase 5 — Web UI integration: chains/coverage/why in page and result payload."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_page_has_phase5_sections():
    from engine import webui
    page = webui.PAGE
    assert 'id="chains-section"' in page
    assert 'id="coverage-section"' in page
    assert 'id="why-section"' in page
    assert "renderResult" in page


def test_build_result_enriches(monkeypatch):
    from engine import webui
    seeded = [{
        "id": 1, "timestamp": "2026-10-10", "pattern_id": "env-file-exposure",
        "category": "content", "verdict": "VULNERABLE", "severity": "high",
        "reason": "/.env served", "wstg_id": "", "cwe_id": "",
        "evidence_path": "", "duration_ms": 5,
    }, {
        "id": 2, "timestamp": "2026-10-10", "pattern_id": "mass-assignment",
        "category": "sequence", "verdict": "VULNERABLE", "severity": "high",
        "reason": "mass assign", "wstg_id": "", "cwe_id": "",
        "evidence_path": "", "duration_ms": 5,
    }]
    monkeypatch.setattr(webui, "_findings_for", lambda target: list(seeded))
    outcome = {"targets": {"api_base": "https://example.com"}, "counts": {}}
    result = webui._build_result("https://example.com", outcome, "log text")
    assert "chains" in result and isinstance(result["chains"], list)
    assert "coverage" in result and result["coverage"] is not None
    assert any("why" in f for f in result["findings"])


def test_build_result_safe_when_no_findings(monkeypatch):
    from engine import webui
    monkeypatch.setattr(webui, "_findings_for", lambda target: [])
    result = webui._build_result("https://example.com", {"targets": {}}, "log")
    assert result["chains"] == []
    assert "coverage" in result
