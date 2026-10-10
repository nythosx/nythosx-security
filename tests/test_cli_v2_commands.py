"""Phase 5 — new CLI commands: chains, coverage."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_commands_registered():
    from engine import cli
    assert "chains" in cli.COMMANDS
    assert "coverage" in cli.COMMANDS


def test_chains_help_returns_zero():
    from engine import cli
    assert cli.cmd_chains(["--help"]) == 0


def test_coverage_help_returns_zero():
    from engine import cli
    assert cli.cmd_coverage(["--help"]) == 0


def test_chains_no_findings(monkeypatch):
    from engine import cli, ledger
    monkeypatch.setattr(ledger, "findings_for_target", lambda t: [])
    monkeypatch.setattr(ledger, "all_targets", lambda: [])
    assert cli.cmd_chains(["http://no-such-target.invalid"]) == 0


def test_coverage_runs(monkeypatch):
    from engine import cli, ledger
    monkeypatch.setattr(ledger, "findings_for_target", lambda t: [])
    monkeypatch.setattr(ledger, "all_targets", lambda: [])
    assert cli.cmd_coverage(["http://no-such-target.invalid"]) == 0


def test_chains_with_findings(monkeypatch):
    from engine import cli, ledger
    row = (1, "2026-10-10", "env-file-exposure", "content", "VULNERABLE",
           "high", "/.env served", "", "", "", 5)
    row2 = (2, "2026-10-10", "mass-assignment", "sequence", "VULNERABLE",
            "high", "mass assign", "", "", "", 5)
    monkeypatch.setattr(ledger, "findings_for_target", lambda t: [row, row2])
    assert cli.cmd_chains(["http://seeded.invalid"]) == 0
