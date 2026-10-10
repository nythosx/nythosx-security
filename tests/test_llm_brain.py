"""LLM brain: provider-agnostic client (OpenAI-compatible / Anthropic / Gemini)."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class _FakeResp:
    def __init__(self, payload):
        self._p = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


class _FakeClient:
    def __init__(self, capture, payload):
        self._capture = capture
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, headers=None, json=None):
        self._capture["url"] = url
        self._capture["headers"] = headers or {}
        self._capture["json"] = json or {}
        return _FakeResp(self._payload)


def _patch_httpx(monkeypatch, capture, payload):
    import httpx
    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: _FakeClient(capture, payload))


def test_make_llm_client_is_callable():
    from engine.brains.llm import make_llm_client
    c = make_llm_client(provider="openai", model="x", api_key="k")
    assert callable(c)


def test_openai_shape(monkeypatch):
    from engine.brains import llm
    cap = {}
    _patch_httpx(monkeypatch, cap,
                 {"choices": [{"message": {"content": "hello-openai"}}]})
    c = llm.make_llm_client(provider="openai", model="gpt-x", api_key="k")
    assert c("hi") == "hello-openai"
    assert cap["url"].endswith("/chat/completions")
    assert cap["headers"].get("Authorization") == "Bearer k"
    assert cap["json"]["temperature"] == 0


def test_anthropic_shape(monkeypatch):
    from engine.brains import llm
    cap = {}
    _patch_httpx(monkeypatch, cap, {"content": [{"text": "hello-claude"}]})
    c = llm.make_llm_client(provider="anthropic", model="claude-x", api_key="k")
    assert c("hi") == "hello-claude"
    assert cap["url"].endswith("/v1/messages")
    assert cap["headers"].get("x-api-key") == "k"


def test_gemini_shape(monkeypatch):
    from engine.brains import llm
    cap = {}
    _patch_httpx(monkeypatch, cap,
                 {"candidates": [{"content": {"parts": [{"text": "hello-gemini"}]}}]})
    c = llm.make_llm_client(provider="gemini", model="gemini-x", api_key="k")
    assert c("hi") == "hello-gemini"
    assert "gemini-x:generateContent" in cap["url"]
    assert cap["headers"].get("x-goog-api-key") == "k"


def test_no_key_raises(monkeypatch):
    from engine.brains import llm
    for name in llm._API_KEY_ENVS:
        monkeypatch.delenv(name, raising=False)
    c = llm.make_llm_client(provider="openai", model="x")
    with pytest.raises(Exception):
        c("hi")


def test_llm_brain_uses_client():
    from engine.brains.llm import LLMBrain
    from engine.state import ScanState
    brain = LLMBrain(client=lambda p: '{"capabilities": ["jwt_advanced", "cors_misconfig"]}')
    state = ScanState(target="https://x")
    hyps = brain.propose(state)
    caps = {h.capability for h in hyps}
    assert "jwt_advanced" in caps and "cors_misconfig" in caps


def test_llm_brain_falls_back_on_bad_json():
    from engine.brains.llm import LLMBrain
    from engine.state import ScanState
    brain = LLMBrain(client=lambda p: "not json at all")
    state = ScanState(target="https://x")
    hyps = brain.propose(state)
    assert isinstance(hyps, list)
