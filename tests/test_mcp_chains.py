import asyncio
import sys
import types

import pytest


def _ensure_claude_agent_sdk():
    if "claude_agent_sdk" in sys.modules:
        return
    try:
        import claude_agent_sdk  # noqa: F401
        return
    except ImportError:
        pass
    mod = types.ModuleType("claude_agent_sdk")

    def tool(name, description, schema=None):
        def deco(fn):
            fn._tool_name = name
            fn._tool_description = description
            fn._tool_schema = schema or {}
            return fn
        return deco

    mod.tool = tool
    sys.modules["claude_agent_sdk"] = mod


_ensure_claude_agent_sdk()


def _run(coro):
    return asyncio.run(coro)


def _permissive_roe():
    return {
        "enabled": True,
        "scope": {
            "in_scope": ["127.0.0.1", "localhost", "test.local",
                          "evil.example.com"],
            "out_of_scope": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_paths": [],
        },
    }


def _restrictive_roe():
    return {
        "enabled": True,
        "scope": {
            "in_scope": ["127.0.0.1"],
            "out_of_scope": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_paths": [],
        },
    }


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr("engine.roe_guard.load_roe", _permissive_roe)
    yield


def test_chains_module_imports():
    from sec_checker_tools import chains
    assert chains is not None


def test_tool_chain_scan_callable():
    from sec_checker_tools.chains import tool_chain_scan
    assert callable(tool_chain_scan)


def test_tool_metadata():
    from sec_checker_tools.chains import tool_chain_scan
    assert getattr(tool_chain_scan, "_tool_name", None) == "chain_scan"
    desc = getattr(tool_chain_scan, "_tool_description", "")
    assert desc
    assert "chain" in desc.lower() or "adaptive" in desc.lower()
    schema = getattr(tool_chain_scan, "_tool_schema", None)
    assert isinstance(schema, dict)
    assert "target" in schema


def test_tool_discoverable_via_registry():
    from sec_checker_tools.registry import discover
    tools = discover()
    names = {getattr(t, "_tool_name", None) or t.__name__ for t in tools}
    assert "chain_scan" in names


def test_existing_tools_still_discoverable():
    from sec_checker_tools.registry import discover
    tools = discover()
    names = {getattr(t, "_tool_name", None) or t.__name__ for t in tools}
    for expected in ("sec_scan", "jwt_attack", "llm_scan", "race_scan",
                     "graphql_scan", "sec_orchestrate"):
        assert expected in names, f"missing tool: {expected}"


def test_tool_missing_target_returns_error():
    from sec_checker_tools.chains import tool_chain_scan
    result = _run(tool_chain_scan({}))
    assert result.get("isError")
    assert "target" in result["content"][0]["text"].lower()


def test_tool_roe_block(monkeypatch):
    monkeypatch.setattr("engine.roe_guard.load_roe", _restrictive_roe)
    from sec_checker_tools.chains import tool_chain_scan
    result = _run(tool_chain_scan({"target": "http://evil.example.com"}))
    assert result.get("isError")
    assert "ROE" in result["content"][0]["text"]


def _fake_run_pass(self, chains=None):
    return {
        "target": self.target,
        "duration_sec": 0.01,
        "verdict": "PASS",
        "facts": {"framework": {"value": "express"}},
        "context": {},
        "recon": {"framework": None, "api_base": None,
                  "js_urls": [], "api_paths": [], "live_paths": [],
                  "errors": []},
        "plan": ["jwt-chain"],
        "chain_results": [{
            "id": "jwt-chain", "name": "JWT",
            "verdict": "PASS", "steps": [], "duration_ms": 5.0,
            "reason": "all rejected",
        }],
        "findings": [],
        "attempts_count": 0,
    }


def _fake_run_vuln(self, chains=None):
    return {
        "target": self.target,
        "duration_sec": 1.0,
        "verdict": "VULNERABLE",
        "facts": {}, "context": {},
        "recon": {"framework": None, "api_base": None,
                  "js_urls": [], "api_paths": [], "live_paths": [],
                  "errors": []},
        "plan": [], "chain_results": [],
        "findings": [{
            "chain": "jwt-chain", "step": "alg_none",
            "tool": "jwt_attack", "verdict": "VULNERABLE",
            "reason": "alg:none accepted",
            "evidence": {}, "timestamp": "2026-01-01T00:00:00Z",
        }],
        "attempts_count": 1,
    }


def test_tool_success_pass(monkeypatch):
    monkeypatch.setattr("engine.chain_engine.ChainOrchestrator.run",
                        _fake_run_pass)
    from sec_checker_tools.chains import tool_chain_scan
    result = _run(tool_chain_scan({"target": "http://test.local"}))
    assert not result.get("isError")
    text = result["content"][0]["text"]
    assert "Attack Chain" in text
    assert "PASS" in text
    assert result["structuredContent"]["verdict"] == "PASS"


def test_tool_success_vulnerable(monkeypatch):
    monkeypatch.setattr("engine.chain_engine.ChainOrchestrator.run",
                        _fake_run_vuln)
    from sec_checker_tools.chains import tool_chain_scan
    result = _run(tool_chain_scan({"target": "http://test.local"}))
    assert not result.get("isError")
    text = result["content"][0]["text"]
    assert "VULNERABLE" in text
    assert "alg:none accepted" in text
    assert result["structuredContent"]["verdict"] == "VULNERABLE"


def _install_filter_mocks(monkeypatch, calls):
    def _fake_recon(self):
        self.recon = {"framework": None, "api_base": "http://x",
                      "js_urls": [], "api_paths": [], "live_paths": [],
                      "errors": []}

    def _fake_execute(self, chain):
        calls.append(chain["id"])
        return {"id": chain["id"], "name": "", "verdict": "PASS",
                "steps": [], "duration_ms": 0.0, "reason": ""}

    def _fake_final(self):
        return {
            "target": self.target, "duration_sec": 0.0,
            "verdict": "UNKNOWN", "facts": {}, "context": {},
            "recon": self.recon, "plan": [],
            "chain_results": [], "findings": [], "attempts_count": 0,
        }

    monkeypatch.setattr(
        "engine.chain_engine.ChainOrchestrator.run_recon", _fake_recon)
    monkeypatch.setattr(
        "engine.chain_engine.ChainOrchestrator.execute_chain", _fake_execute)
    monkeypatch.setattr(
        "engine.chain_engine.ChainOrchestrator._final_report", _fake_final)


def test_tool_chain_filter(monkeypatch):
    calls = []
    _install_filter_mocks(monkeypatch, calls)
    from sec_checker_tools.chains import tool_chain_scan
    result = _run(tool_chain_scan({
        "target": "http://test.local",
        "chains": "jwt-chain,graphql-chain",
    }))
    assert not result.get("isError")
    assert set(calls) == {"jwt-chain", "graphql-chain"}


def test_tool_chain_filter_no_matches(monkeypatch):
    from sec_checker_tools.chains import tool_chain_scan
    result = _run(tool_chain_scan({
        "target": "http://test.local",
        "chains": "does-not-exist",
    }))
    assert result.get("isError")
    assert "No chains" in result["content"][0]["text"]


def test_tool_sca_path_injects_facts(monkeypatch):
    captured = {}

    def _fake_recon(self):
        self.recon = {"framework": None, "api_base": "http://x",
                      "js_urls": [], "api_paths": [], "live_paths": [],
                      "errors": []}
        captured["facts"] = dict(self.facts)
        captured["context"] = dict(self.context)

    def _fake_execute(self, chain):
        return {"id": chain["id"], "name": "", "verdict": "PASS",
                "steps": [], "duration_ms": 0.0, "reason": ""}

    def _fake_final(self):
        return {
            "target": self.target, "duration_sec": 0.0,
            "verdict": "UNKNOWN", "facts": {}, "context": {},
            "recon": self.recon, "plan": [],
            "chain_results": [], "findings": [], "attempts_count": 0,
        }

    monkeypatch.setattr(
        "engine.chain_engine.ChainOrchestrator.run_recon", _fake_recon)
    monkeypatch.setattr(
        "engine.chain_engine.ChainOrchestrator.execute_chain", _fake_execute)
    monkeypatch.setattr(
        "engine.chain_engine.ChainOrchestrator._final_report", _fake_final)

    from sec_checker_tools.chains import tool_chain_scan
    result = _run(tool_chain_scan({
        "target": "http://test.local",
        "chains": "sca-chain",
        "sca_path": "/tmp/project",
    }))
    assert not result.get("isError")
    assert captured["facts"].get("sca_requested", {}).get("value") is True
    assert captured["context"].get("sca_path") == "/tmp/project"
