
import pytest

from engine import cli
from engine import chain_engine


def test_chain_registered():
    assert "chain" in cli.COMMANDS
    assert cli.COMMANDS["chain"] is cli.cmd_chain


def test_print_chain_report_exists():
    assert callable(cli._print_chain_report)


def test_cmd_chain_help_returns_zero():
    assert cli.cmd_chain(["--help"]) == 0


def test_cmd_chain_short_help_returns_zero():
    assert cli.cmd_chain(["-h"]) == 0


def test_cmd_chain_no_args_returns_none():
    assert cli.cmd_chain([]) is None


def test_cmd_chain_out_of_scope(monkeypatch):
    def _block(self, *a, **k):
        from engine.roe_guard import ROEViolation
        raise ROEViolation("test block")
    monkeypatch.setattr("engine.roe_guard.ROEGuard.check_url", _block)
    result = cli.cmd_chain(["http://evil.example.com"])
    assert result == 1


def test_cmd_chain_no_matching_filter(monkeypatch):
    def _allow(self, *a, **k):
        return True
    monkeypatch.setattr("engine.roe_guard.ROEGuard.check_url", _allow)
    result = cli.cmd_chain([
        "http://test.local",
        "--chain", "does-not-exist",
    ])
    assert result == 1


def test_cmd_chain_json_output(monkeypatch, capsys):
    def _allow(self, *a, **k):
        return True
    monkeypatch.setattr("engine.roe_guard.ROEGuard.check_url", _allow)

    def _fake_run(self, chains=None):
        return {
            "target": self.target,
            "duration_sec": 0.01,
            "verdict": "UNKNOWN",
            "facts": {}, "context": {},
            "recon": {"framework": None, "api_base": None,
                      "js_urls": [], "api_paths": [], "live_paths": [],
                      "errors": []},
            "plan": [], "chain_results": [], "findings": [],
            "attempts_count": 0,
        }

    monkeypatch.setattr(chain_engine.ChainOrchestrator, "run", _fake_run)

    result = cli.cmd_chain(["http://test.local", "--json"])
    assert result == 0
    captured = capsys.readouterr()
    assert '"target"' in captured.out
    assert '"verdict"' in captured.out


def test_cmd_chain_fail_on_with_finding(monkeypatch, capsys):
    def _allow(self, *a, **k):
        return True
    monkeypatch.setattr("engine.roe_guard.ROEGuard.check_url", _allow)

    def _fake_run(self, chains=None):
        return {
            "target": self.target,
            "duration_sec": 0.01,
            "verdict": "VULNERABLE",
            "facts": {}, "context": {},
            "recon": {"framework": None, "api_base": None,
                      "js_urls": [], "api_paths": [], "live_paths": [],
                      "errors": []},
            "plan": [],
            "chain_results": [],
            "findings": [{
                "chain": "test", "step": "s1", "tool": "jwt_attack",
                "verdict": "VULNERABLE", "reason": "boom",
                "evidence": {"severity": "high"},
                "timestamp": "2026-01-01T00:00:00Z",
            }],
            "attempts_count": 1,
        }

    monkeypatch.setattr(chain_engine.ChainOrchestrator, "run", _fake_run)

    result = cli.cmd_chain(["http://test.local", "--fail-on", "high"])
    assert result == cli.EXIT_FINDINGS


def test_cmd_chain_fail_on_below_threshold(monkeypatch):
    def _allow(self, *a, **k):
        return True
    monkeypatch.setattr("engine.roe_guard.ROEGuard.check_url", _allow)

    def _fake_run(self, chains=None):
        return {
            "target": self.target,
            "duration_sec": 0.01,
            "verdict": "PASS",
            "facts": {}, "context": {},
            "recon": {"framework": None, "api_base": None,
                      "js_urls": [], "api_paths": [], "live_paths": [],
                      "errors": []},
            "plan": [], "chain_results": [], "findings": [],
            "attempts_count": 0,
        }

    monkeypatch.setattr(chain_engine.ChainOrchestrator, "run", _fake_run)

    result = cli.cmd_chain(["http://test.local", "--fail-on", "critical"])
    assert result == 0


def test_cmd_chain_chain_filter(monkeypatch, capsys):
    def _allow(self, *a, **k):
        return True
    monkeypatch.setattr("engine.roe_guard.ROEGuard.check_url", _allow)

    calls = []

    def _fake_recon(self):
        calls.append("recon")
        self.recon = {
            "framework": {"id": "generic", "name": "Generic", "score": 0},
            "api_base": "http://test.local",
            "js_urls": [], "api_paths": [], "live_paths": [], "errors": [],
        }

    def _fake_execute(self, chain):
        calls.append(("exec", chain["id"]))
        return {
            "id": chain["id"], "name": chain.get("name", chain["id"]),
            "verdict": "PASS", "steps": [], "duration_ms": 0.0,
            "reason": "", "finding": None,
        }

    def _fake_final(self):
        return {
            "target": self.target, "duration_sec": 0.0,
            "verdict": "UNKNOWN", "facts": {}, "context": {},
            "recon": self.recon, "plan": [],
            "chain_results": [], "findings": [], "attempts_count": 0,
        }

    monkeypatch.setattr(chain_engine.ChainOrchestrator, "run_recon", _fake_recon)
    monkeypatch.setattr(chain_engine.ChainOrchestrator, "execute_chain",
                        _fake_execute)
    monkeypatch.setattr(chain_engine.ChainOrchestrator, "_final_report",
                        _fake_final)

    result = cli.cmd_chain(["http://test.local", "--chain", "jwt-chain"])
    assert result == 0
    assert "recon" in calls
    assert ("exec", "jwt-chain") in calls
    executed = [c[1] for c in calls if isinstance(c, tuple)]
    assert executed == ["jwt-chain"]


def test_cmd_chain_multiple_chain_filter(monkeypatch, capsys):
    def _allow(self, *a, **k):
        return True
    monkeypatch.setattr("engine.roe_guard.ROEGuard.check_url", _allow)

    calls = []

    def _fake_recon(self):
        self.recon = {
            "framework": None, "api_base": "http://test.local",
            "js_urls": [], "api_paths": [], "live_paths": [], "errors": [],
        }

    def _fake_execute(self, chain):
        calls.append(chain["id"])
        return {
            "id": chain["id"], "name": chain.get("name", chain["id"]),
            "verdict": "PASS", "steps": [], "duration_ms": 0.0,
            "reason": "", "finding": None,
        }

    def _fake_final(self):
        return {
            "target": self.target, "duration_sec": 0.0,
            "verdict": "UNKNOWN", "facts": {}, "context": {},
            "recon": self.recon, "plan": [],
            "chain_results": [], "findings": [], "attempts_count": 0,
        }

    monkeypatch.setattr(chain_engine.ChainOrchestrator, "run_recon", _fake_recon)
    monkeypatch.setattr(chain_engine.ChainOrchestrator, "execute_chain",
                        _fake_execute)
    monkeypatch.setattr(chain_engine.ChainOrchestrator, "_final_report",
                        _fake_final)

    result = cli.cmd_chain([
        "http://test.local",
        "--chain", "jwt-chain", "--chain", "graphql-chain",
    ])
    assert result == 0
    assert set(calls) == {"jwt-chain", "graphql-chain"}


def test_cmd_chain_sca_path_injects_facts(monkeypatch):
    def _allow(self, *a, **k):
        return True
    monkeypatch.setattr("engine.roe_guard.ROEGuard.check_url", _allow)

    captured = {}

    def _fake_recon(self):
        self.recon = {"framework": None, "api_base": "http://x",
                      "js_urls": [], "api_paths": [], "live_paths": [],
                      "errors": []}
        captured["facts"] = dict(self.facts)
        captured["context"] = dict(self.context)

    def _fake_execute(self, chain):
        return {"id": chain["id"], "verdict": "PASS", "steps": [],
                "duration_ms": 0.0, "name": "", "reason": "", "finding": None}

    def _fake_final(self):
        return {
            "target": self.target, "duration_sec": 0.0,
            "verdict": "UNKNOWN", "facts": {}, "context": {},
            "recon": self.recon, "plan": [],
            "chain_results": [], "findings": [], "attempts_count": 0,
        }

    monkeypatch.setattr(chain_engine.ChainOrchestrator, "run_recon", _fake_recon)
    monkeypatch.setattr(chain_engine.ChainOrchestrator, "execute_chain",
                        _fake_execute)
    monkeypatch.setattr(chain_engine.ChainOrchestrator, "_final_report",
                        _fake_final)

    result = cli.cmd_chain([
        "http://test.local",
        "--chain", "sca-chain",
        "--with-sca", "/tmp/project",
    ])
    assert result == 0
    assert captured["facts"].get("sca_requested", {}).get("value") is True
    assert captured["context"].get("sca_path") == "/tmp/project"
