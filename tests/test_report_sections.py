"""Phase 5 — report.py integration: Attack Chains, Why This Matters, Coverage."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _vuln(pid, sev="high"):
    return {"id": 1, "pattern_id": pid, "category": "x", "verdict": "VULNERABLE",
            "severity": sev, "reason": f"{pid} hit", "wstg_id": "", "cwe_id": "",
            "evidence_path": "", "duration_ms": 1}


def test_enrich_adds_why():
    from engine import report
    findings = [_vuln("env-file-exposure")]
    report.enrich_findings(findings)
    assert "why" in findings[0]
    assert set(findings[0]["why"]).issuperset({"attack", "gap", "impact", "fix"})


def test_build_chains_returns_chain_with_narrative():
    from engine import report
    findings = [_vuln("env-file-exposure"), _vuln("mass-assignment")]
    chains = report.build_chains(findings)
    assert isinstance(chains, list) and chains
    top = chains[0]
    assert "verdict" in top and "name" in top
    assert "narrative_text" in top


def test_build_coverage_reports_executed():
    from engine import report
    findings = [_vuln("env-file-exposure")]
    cov = report.build_coverage("https://example.com", findings)
    assert cov is not None
    assert cov["executed_count"] >= 1
    assert cov["total_count"] >= 1
    assert "owasp" in cov


def test_html_template_has_all_sections():
    from engine import report
    findings = [_vuln("env-file-exposure")]
    report.enrich_findings(findings)
    chains = report.build_chains(findings)
    cov = report.build_coverage("https://example.com", findings)
    html = report._HTML_ENV.from_string(report.HTML_TEMPLATE).render(
        target="x", timestamp="now", findings=findings,
        counts=report._counts(findings), chains=chains, coverage=cov)
    assert "Attack Chains" in html
    assert "Why this matters" in html
    assert "Coverage" in html


def test_md_template_has_all_sections():
    from engine import report
    findings = [_vuln("env-file-exposure")]
    report.enrich_findings(findings)
    chains = report.build_chains(findings)
    cov = report.build_coverage("https://example.com", findings)
    md = report._MD_ENV.from_string(report.MD_TEMPLATE).render(
        target="x", timestamp="now", findings=findings,
        counts=report._counts(findings), chains=chains, coverage=cov)
    assert "## Attack Chains" in md
    assert "## Why This Matters" in md
    assert "## Coverage" in md


def test_no_data_renders_without_sections():
    from engine import report
    html = report._HTML_ENV.from_string(report.HTML_TEMPLATE).render(
        target="x", timestamp="now", findings=[], counts=report._counts([]),
        chains=[], coverage=None)
    assert "Attack Chains" not in html
    assert "Security Assessment Report" in html
