import pytest

from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["test.local", "127.0.0.1", "localhost"],
                  "out_of_scope": [],
                  "allowed_methods": ["GET", "POST", "PUT", "PATCH",
                                       "DELETE", "OPTIONS", "HEAD"],
                  "forbidden_paths": []},
    })


def test_severity_default_mapping():
    from engine.hunt import _severity_for
    assert _severity_for({}, "VULNERABLE") == "high"
    assert _severity_for({}, "SUSPICIOUS") == "medium"
    assert _severity_for({}, "PASS") == "info"
    assert _severity_for({}, "UNKNOWN") == "info"


def test_severity_override():
    from engine.hunt import _severity_for
    assert _severity_for({"severity": "critical"}, "VULNERABLE") == "critical"
    assert _severity_for({"severity": "low"}, "VULNERABLE") == "low"
    assert _severity_for({"severity": "bogus"}, "VULNERABLE") == "high"


def test_collect_from_report_dedupes():
    from engine.hunt import _collect_from_report, _dedupe_and_sort
    report = {"findings": [
        {"chain": "a", "step": "s1", "tool": "t1", "verdict": "VULNERABLE",
         "reason": "same reason", "evidence": {"severity": "critical"}},
        {"chain": "b", "step": "s2", "tool": "t2", "verdict": "SUSPICIOUS",
         "reason": "other reason", "evidence": {}},
        {"chain": "a", "step": "s1", "tool": "t1", "verdict": "VULNERABLE",
         "reason": "same reason", "evidence": {"severity": "critical"}},
    ]}
    raw = _collect_from_report(report)
    assert len(raw) == 3
    unique = _dedupe_and_sort(raw)
    assert len(unique) == 2
    assert unique[0]["severity"] == "critical"
    assert unique[1]["severity"] == "medium"


def test_dedupe_and_sort_by_severity():
    from engine.hunt import _dedupe_and_sort
    findings = [
        {"chain": "a", "step": "s1", "severity": "low", "reason": "r1"},
        {"chain": "b", "step": "s2", "severity": "critical", "reason": "r2"},
        {"chain": "c", "step": "s3", "severity": "high", "reason": "r3"},
    ]
    out = _dedupe_and_sort(findings)
    assert [f["severity"] for f in out] == ["critical", "high", "low"]


def test_dedupe_and_sort_stable_on_confidence():
    from engine.hunt import _dedupe_and_sort
    findings = [
        {"chain": "a", "step": "s1", "severity": "critical",
         "reason": "r1", "confidence": 0.4},
        {"chain": "b", "step": "s2", "severity": "critical",
         "reason": "r2", "confidence": 0.9},
    ]
    out = _dedupe_and_sort(findings)
    assert out[0]["confidence"] == 0.9
    assert out[1]["confidence"] == 0.4


def test_hunt_returns_structured_report(monkeypatch, tmp_path):
    from engine import ledger
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")

    canned = {
        "target": "http://test.local",
        "verdict": "VULNERABLE",
        "facts": {"framework": {"value": "express"}},
        "recon": {"framework": {"id": "express", "name": "Express", "score": 9},
                  "api_base": "http://test.local/api",
                  "js_urls": [], "api_paths": [], "live_paths": [], "errors": []},
        "findings": [
            {"chain": "x", "step": "alg_none", "tool": "jwt_attack",
             "verdict": "VULNERABLE", "reason": "alg:none accepted",
             "evidence": {"severity": "critical"}},
        ],
        "chain_results": [],
        "context": {},
    }
    monkeypatch.setattr(
        "engine.chain_engine.ChainOrchestrator.run",
        lambda self, chains=None: canned)

    from engine import hunt as hunt_mod
    report = hunt_mod.hunt("http://test.local", include_standalone=False,
                           verbose=False, budget_sec=10)
    assert report["total_findings"] == 1
    assert report["findings"][0]["severity"] == "critical"
    assert report["findings"][0]["verdict"] == "VULNERABLE"
    assert report["verdict"] == "VULNERABLE"
    assert "duration_sec" in report
    assert "generated_at" in report


def test_hunt_handles_empty_findings(monkeypatch, tmp_path):
    from engine import ledger
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")

    canned = {
        "target": "http://test.local",
        "verdict": "PASS",
        "facts": {},
        "recon": {"framework": {"id": "generic", "name": "Generic", "score": 0},
                  "api_base": None, "js_urls": [], "api_paths": [],
                  "live_paths": [], "errors": []},
        "findings": [],
        "chain_results": [],
        "context": {},
    }
    monkeypatch.setattr("engine.chain_engine.ChainOrchestrator.run",
                        lambda self, chains=None: canned)

    from engine import hunt as hunt_mod
    report = hunt_mod.hunt("http://test.local", include_standalone=False,
                           verbose=False, budget_sec=10)
    assert report["total_findings"] == 0
    assert report["findings"] == []
    assert report["verdict"] == "PASS"


def test_hunt_respects_roe_block(monkeypatch, tmp_path):
    from engine import roe_guard as roe_mod
    from engine import ledger
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })

    from engine import hunt as hunt_mod
    with pytest.raises(RuntimeError, match="ROE_BLOCK"):
        hunt_mod.hunt("http://127.0.0.1:1", include_standalone=False,
                      verbose=False, budget_sec=10)


def test_hunt_truncates_to_max_findings(monkeypatch, tmp_path):
    from engine import ledger
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")

    many = [
        {"chain": f"c{i}", "step": f"s{i}", "tool": f"t{i}",
         "verdict": "VULNERABLE", "reason": f"r{i}",
         "evidence": {"severity": "high"}}
        for i in range(50)
    ]
    canned = {
        "target": "http://test.local", "verdict": "VULNERABLE",
        "facts": {},
        "recon": {"framework": {}, "api_base": None, "js_urls": [],
                  "api_paths": [], "live_paths": [], "errors": []},
        "findings": many, "chain_results": [], "context": {},
    }
    monkeypatch.setattr("engine.chain_engine.ChainOrchestrator.run",
                        lambda self, chains=None: canned)

    from engine import hunt as hunt_mod
    report = hunt_mod.hunt("http://test.local", include_standalone=False,
                           verbose=False, budget_sec=10, max_findings=5)
    assert report["total_findings"] == 50
    assert len(report["findings"]) == 5


def test_cli_hunt_registered():
    from engine import cli
    assert "hunt" in cli.COMMANDS
    assert callable(cli.COMMANDS["hunt"])


def test_cli_hunt_help_returns_zero():
    from engine import cli
    assert cli.cmd_hunt(["--help"]) == 0
    assert cli.cmd_hunt(["-h"]) == 0
