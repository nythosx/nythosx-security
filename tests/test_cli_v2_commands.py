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


def test_global_flags_include_phase6():
    from engine import cli
    for flag in ("--waf", "--no-waf", "--confirm", "--no-confirm",
                 "--iterate", "--iteration-max"):
        assert flag in cli._GLOBAL_FLAGS, "missing global flag: " + flag


def test_runtime_dict_has_phase6_defaults():
    from engine import cli
    for key in ("waf_enabled", "waf_disabled", "confirm_enabled",
                "confirm_disabled", "iterate_enabled", "iteration_max"):
        assert key in cli.RUNTIME, "missing runtime key: " + key


def test_parse_global_flags_iterate():
    from engine import cli
    saved = dict(cli.RUNTIME)
    try:
        cli.RUNTIME["waf_enabled"] = False
        cli.RUNTIME["iterate_enabled"] = False
        cli.RUNTIME["iteration_max"] = None
        rest = cli._parse_global_flags([
            "--waf", "--iterate", "--iteration-max", "5",
            "chain", "http://x"])
        assert rest == ["chain", "http://x"]
        assert cli.RUNTIME["waf_enabled"] is True
        assert cli.RUNTIME["iterate_enabled"] is True
        assert cli.RUNTIME["iteration_max"] == 5
    finally:
        cli.RUNTIME.clear()
        cli.RUNTIME.update(saved)


def test_help_mentions_new_flags(capsys):
    from engine import cli
    cli.cmd_help([])
    out = capsys.readouterr().out
    for flag in ("--waf", "--confirm", "--iterate", "--iteration-max"):
        assert flag in out, "help missing: " + flag


def test_chains_with_findings(monkeypatch):
    from engine import cli, ledger
    row = (1, "2026-10-10", "env-file-exposure", "content", "VULNERABLE",
           "high", "/.env served", "", "", "", 5)
    row2 = (2, "2026-10-10", "mass-assignment", "sequence", "VULNERABLE",
            "high", "mass assign", "", "", "", 5)
    monkeypatch.setattr(ledger, "findings_for_target", lambda t: [row, row2])
    assert cli.cmd_chains(["http://seeded.invalid"]) == 0
