import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_new_cli_commands_registered():
    from engine import cli
    for name in ("cve", "bypass", "cached"):
        assert name in cli.COMMANDS, f"missing CLI command: {name}"
        assert callable(cli.COMMANDS[name])


def test_cmd_llm_has_no_dead_branch():
    src = (ROOT / "engine" / "cli.py").read_text(encoding="utf-8")
    dead_block = (
        '        console.print("[red]Usage: llm <url> [--model MODEL] [--api-key KEY] "\n'
        '                      "[--auth X] [--session NAME] [--fail-on SEV][/red]")\n'
        '        return\n'
        '    url = args[0]'
    )
    assert dead_block not in src, (
        "cmd_llm still has the duplicate 'if not args' dead branch")


def test_cmd_cve_help_returns_zero():
    from engine import cli
    assert cli.cmd_cve(["--help"]) == 0
    assert cli.cmd_bypass(["--help"]) == 0
    assert cli.cmd_cached(["--help"]) == 0


def test_cmd_cve_missing_args_returns_zero():
    from engine import cli
    assert cli.cmd_cve([]) == 0


def test_auto_routes_through_chain_engine():
    src = (ROOT / "engine" / "auto.py").read_text(encoding="utf-8")
    assert "ChainOrchestrator" in src
    assert "run_auto_compat" not in src


def test_chain_registry_new_chains_present():
    from engine.chain_registry import get_all_chains
    ids = {c["id"] for c in get_all_chains()}
    for cid in ("cve-chain", "access-bypass-chain", "cache-deception-chain"):
        assert cid in ids


def test_chain_tool_handlers_present():
    from engine.chain_engine import ChainOrchestrator
    handlers = ChainOrchestrator._TOOL_HANDLERS
    for tool in ("cve_correlation", "access_bypass", "cache_deception"):
        assert tool in handlers
        assert callable(handlers[tool])


def test_oracle_handlers_present():
    from engine.oracle import _HANDLERS
    for otype in ("cve_correlation", "access_bypass_scan", "cache_deception_scan"):
        assert otype in _HANDLERS


def test_narrator_has_chain_templates():
    from engine import narrator
    for etype in ("plan", "fact", "chain_start", "chain_done",
                  "step_start", "step_done"):
        assert etype in narrator._TEMPLATES
    r = narrator.narrate("chain_start", {"id": "jwt-chain", "name": "JWT Chain"})
    assert r is not None
    assert r["type"] == "action"


def test_narrator_chain_done_vulnerable():
    from engine import narrator
    r = narrator.narrate("chain_done", {
        "id": "cve-chain", "verdict": "VULNERABLE",
        "reason": "3 critical CVEs", "duration_ms": 120,
    })
    assert r["type"] == "vuln"


def test_narrator_step_done_labels():
    from engine import narrator
    r = narrator.narrate("step_done", {
        "chain": "access-bypass-chain", "step": "access_bypass",
        "tool": "access_bypass", "verdict": "VULNERABLE",
        "reason": "X-Original-URL flipped 403 to 200",
    })
    assert r is not None
    assert "access bypass" in r["text"].lower()


def test_report_context_includes_cves(monkeypatch, tmp_path):
    from engine import ledger, report

    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")

    target = "http://127.0.0.1:9999/api/admin"

    ledger.record_finding(
        pattern_id="chain-cve_correlation",
        target=target,
        verdict="VULNERABLE",
        severity="high",
        reason="2 CVEs for nginx 1.18.0",
        evidence_path="",
        evidence_json={
            "product": "nginx",
            "version": "1.18.0",
            "cves": [
                {"id": "CVE-2021-23017", "severity": "high",
                 "summary": "resolver overflow"},
                {"id": "CVE-2019-20372", "severity": "medium",
                 "summary": "request smuggling"},
            ],
        },
        category="chain",
    )

    ctx = report._build_context(target, engine_cfg={"report": {}})
    assert "cves" in ctx
    ids = {c["id"] for c in ctx["cves"]}
    assert "CVE-2021-23017" in ids
    assert "CVE-2019-20372" in ids


def test_report_context_severity_escalation(monkeypatch, tmp_path):
    from engine import ledger, report

    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")

    target = "http://127.0.0.1:9999/api/admin"
    ledger.record_finding(
        pattern_id="cors-wildcard",
        target=target,
        verdict="VULNERABLE",
        severity="low",
        reason="cors reflected",
        evidence_path="",
        evidence_json={},
        category="single",
    )

    ctx = report._build_context(target, engine_cfg={"report": {}})
    assert ctx["findings"], "no findings loaded"
    assert ctx["findings"][0]["severity"] == "critical", (
        f"severity not escalated: {ctx['findings'][0]['severity']}")


def test_chain_engine_records_to_ledger(monkeypatch, tmp_path):
    from engine import ledger, chain_engine

    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")

    calls = []
    real_record = ledger.record_finding

    def _spy(*args, **kwargs):
        calls.append(kwargs.get("pattern_id") or (args[0] if args else None))
        return real_record(*args, **kwargs)

    monkeypatch.setattr(ledger, "record_finding", _spy)

    class _Allow:
        def check_url(self, url, method="GET"):
            return True

    orch = chain_engine.ChainOrchestrator(
        "http://test.local", roe_guard=_Allow(), engine_cfg={})
    orch._record_finding(
        "test-chain",
        {"id": "s1", "tool": "cve_correlation"},
        {"verdict": "VULNERABLE", "reason": "boom",
         "evidence": {"severity": "high", "cves": []}},
    )
    assert any("chain-cve_correlation" == c for c in calls), (
        f"ledger not written: {calls}")


def test_ledger_findings_for_target_includes_evidence_json(monkeypatch, tmp_path):
    from engine import ledger

    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    target = "http://127.0.0.1:8888/api"
    ledger.record_finding(
        pattern_id="chain-cve_correlation",
        target=target,
        verdict="VULNERABLE",
        severity="high",
        reason="x",
        evidence_path="",
        evidence_json={"cves": [{"id": "CVE-2024-0001"}]},
        category="chain",
    )
    rows = ledger.findings_for_target(target)
    assert rows, "no rows returned"
    assert len(rows[0]) >= 12, (
        f"expected evidence_json column, got {len(rows[0])} columns")


def test_report_html_template_has_cve_section():
    from engine import report
    assert "Known Vulnerabilities" in report.HTML_TEMPLATE
    assert "nvd.nist.gov" in report.HTML_TEMPLATE


def test_report_md_template_has_cve_section():
    from engine import report
    assert "Known Vulnerabilities" in report.MD_TEMPLATE


def test_report_html_renders_cves():
    from engine import report
    html = report._HTML_ENV.from_string(report.HTML_TEMPLATE).render(
        target="http://x", timestamp="now", findings=[],
        counts=report._counts([]), chains=[], coverage=None,
        cves=[{"id": "CVE-2024-0001", "severity": "critical",
               "product": "nginx", "version": "1.18.0",
               "summary": "resolver overflow"}])
    assert "Known Vulnerabilities" in html
    assert "CVE-2024-0001" in html
    assert "nginx" in html


def test_auto_outcome_shape():
    from engine.auto import _chain_report_to_outcome

    report = {
        "target": "http://example.local",
        "verdict": "VULNERABLE",
        "facts": {
            "api_base": {"value": "http://example.local/api"},
            "api_source": {"value": "same-origin"},
            "catch_all": {"value": False},
        },
        "recon": {
            "framework": {"id": "express", "name": "Express", "score": 9},
            "api_base": "http://example.local/api",
            "js_urls": [],
            "api_paths": ["/api/users"],
            "live_paths": [],
            "errors": [],
        },
        "chain_results": [
            {"id": "cve-chain", "verdict": "VULNERABLE",
             "steps": [{"id": "cve_corr", "verdict": "VULNERABLE",
                        "tool": "cve_correlation"}]},
        ],
        "findings": [],
    }
    outcome = _chain_report_to_outcome(report, "http://example.local")
    assert outcome["framework"]["adapter"]["id"] == "express"
    assert outcome["targets"]["api_base"] == "http://example.local/api"
    assert outcome["counts"]["VULNERABLE"] == 1
    assert outcome["report_target"] == "http://example.local/api"
    assert len(outcome["results"]) == 1
    assert outcome["results"][0]["verdict"] == "VULNERABLE"


def test_auto_outcome_empty_report():
    from engine.auto import _chain_report_to_outcome

    outcome = _chain_report_to_outcome({}, "http://x")
    assert outcome["counts"]["VULNERABLE"] == 0
    assert outcome["report_target"] == "http://x"
    assert outcome["framework"]["adapter"]["id"] == "generic"
