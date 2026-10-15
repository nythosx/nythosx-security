from engine import llm_service


def _cfg(**brain):
    return brain


def test_resolve_universal_default():
    cfg = {"enabled": True, "llm": {"provider": "gemini",
                                    "model": "gemini-x", "api_key_env": "K"}}
    r = llm_service.resolve("oracle", cfg=cfg)
    assert r["provider"] == "gemini"
    assert r["model"] == "gemini-x"
    assert r["api_key_env"] == "K"


def test_resolve_per_tool_override():
    cfg = {"enabled": True,
           "llm": {"provider": "gemini", "model": "gemini-x", "api_key_env": "K"},
           "tools": {"oracle": {"provider": "openai", "model": "gpt-4o-mini",
                                "api_key_env": "OK"}}}
    r = llm_service.resolve("oracle", cfg=cfg)
    assert r["provider"] == "openai"
    assert r["model"] == "gpt-4o-mini"
    assert r["api_key_env"] == "OK"
    other = llm_service.resolve("payload_author", cfg=cfg)
    assert other["provider"] == "gemini"


def test_resolve_disabled_returns_none():
    assert llm_service.resolve("oracle", cfg={"enabled": False,
                                              "llm": {"provider": "gemini"}}) is None
    assert llm_service.resolve("oracle", cfg={"enabled": True,
                                              "llm": {"provider": ""}}) is None
    assert llm_service.resolve("oracle", cfg={"enabled": True,
                                              "llm": {"provider": "rule_based"}}) is None


def test_get_client_none_without_key(monkeypatch):
    for n in ("SECCHECKER_LLM_API_KEY", "LLM_API_KEY", "ANTHROPIC_API_KEY",
              "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
              "GROQ_API_KEY", "OPENROUTER_API_KEY", "ZZ_KEY"):
        monkeypatch.delenv(n, raising=False)
    cfg = {"enabled": True, "llm": {"provider": "gemini", "api_key_env": "ZZ_KEY"}}
    assert llm_service.get_client("oracle", cfg=cfg) is None
    assert llm_service.is_enabled("oracle", cfg=cfg) is False


def test_get_client_built_with_key(monkeypatch):
    monkeypatch.setenv("ZZ_KEY", "secret")
    cfg = {"enabled": True, "llm": {"provider": "gemini", "api_key_env": "ZZ_KEY"}}
    client = llm_service.get_client("oracle", cfg=cfg)
    assert callable(client)


def test_complete_falls_back_to_default_without_llm(monkeypatch):
    for n in ("SECCHECKER_LLM_API_KEY", "LLM_API_KEY", "ANTHROPIC_API_KEY",
              "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
              "GROQ_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(n, raising=False)
    cfg = {"enabled": False}
    assert llm_service.complete("hi", capability="oracle", cfg=cfg,
                                default="FALLBACK") == "FALLBACK"
