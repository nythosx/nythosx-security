import sys
import types


def _ensure_claude_agent_sdk():
    if getattr(sys.modules.get("mcp.server"), "_is_scopes_stub", False):
        return
    for key in list(sys.modules.keys()):
        if key == "claude_agent_sdk" or key == "mcp" \
                or key.startswith("mcp.") or key == "sec_checker_mcp" \
                or key.startswith("sec_checker_tools"):
            del sys.modules[key]
    sdk = types.ModuleType("claude_agent_sdk")
    sdk._is_test_stub = True

    def tool(name, description, schema=None):
        def deco(fn):
            fn._tool_name = name
            fn._tool_description = description
            fn._tool_schema = schema or {}
            return fn
        return deco

    sdk.tool = tool
    sys.modules["claude_agent_sdk"] = sdk

    mcp = types.ModuleType("mcp")
    mcp_server = types.ModuleType("mcp.server")
    mcp_stdio = types.ModuleType("mcp.server.stdio")
    mcp_types = types.ModuleType("mcp.types")

    class _Server:
        def __init__(self, name):
            self.name = name

        def list_tools(self):
            return lambda f: f

        def call_tool(self):
            return lambda f: f

        async def run(self, *a, **k):
            pass

        def create_initialization_options(self):
            return {}

    class _TextContent:
        def __init__(self, type, text):
            self.type = type
            self.text = text

    async def _stdio_server():
        class _Ctx:
            async def __aenter__(self_inner):
                return (None, None)
            async def __aexit__(self_inner, *a):
                return False
        return _Ctx()

    mcp_server._is_scopes_stub = True
    mcp_server.Server = _Server
    mcp_stdio.stdio_server = _stdio_server
    mcp_types.Tool = object
    mcp_types.TextContent = _TextContent
    sys.modules["mcp"] = mcp
    sys.modules["mcp.server"] = mcp_server
    sys.modules["mcp.server.stdio"] = mcp_stdio
    sys.modules["mcp.types"] = mcp_types


_ensure_claude_agent_sdk()


def _load_mcp():
    _ensure_claude_agent_sdk()
    if "sec_checker_mcp" in sys.modules:
        del sys.modules["sec_checker_mcp"]
    import importlib
    return importlib.import_module("sec_checker_mcp")


def test_read_scope_grants_read_tool():
    m = _load_mcp()
    ok, reason = m.authorize("sec_scan", frozenset({"scan:read"}))
    assert ok
    assert reason is None


def test_read_scope_denies_destructive_tool():
    m = _load_mcp()
    ok, reason = m.authorize("race_scan", frozenset({"scan:read"}))
    assert not ok
    assert "scan:destructive" in reason


def test_destructive_scope_grants_destructive_tool():
    m = _load_mcp()
    ok, reason = m.authorize("race_scan",
                              frozenset({"scan:read", "scan:destructive"}))
    assert ok


def test_unknown_tool_authorized():
    m = _load_mcp()
    ok, _ = m.authorize("never_heard_of_it", frozenset())
    assert ok


def test_default_scopes_are_read_only(monkeypatch):
    monkeypatch.delenv("SEC_CHECKER_MCP_SCOPES", raising=False)
    m = _load_mcp()
    assert m._granted_scopes() == frozenset({"scan:read"})


def test_env_var_overrides_scopes(monkeypatch):
    monkeypatch.setenv("SEC_CHECKER_MCP_SCOPES",
                       "scan:read,scan:destructive")
    m = _load_mcp()
    assert "scan:destructive" in m._granted_scopes()


def test_upload_scan_requires_destructive():
    m = _load_mcp()
    ok, _ = m.authorize("upload_scan", frozenset({"scan:read"}))
    assert not ok


def test_workflow_list_params_is_read():
    m = _load_mcp()
    ok, _ = m.authorize("workflow_list_params", frozenset({"scan:read"}))
    assert ok


def test_workflow_tamper_is_destructive():
    m = _load_mcp()
    ok, _ = m.authorize("workflow_tamper", frozenset({"scan:read"}))
    assert not ok
