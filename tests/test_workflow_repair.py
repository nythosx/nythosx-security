import json

from engine import workflow_recorder as wr
from engine import llm_service


def test_repair_no_ai_returns_none(monkeypatch):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    assert wr._llm_repair_selector("#old", "<html></html>", "err") is None


def test_repair_returns_new_selector(monkeypatch):
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: (
            lambda p: json.dumps({"selector": "button.submit-v2"})))
    out = wr._llm_repair_selector("#submit", "<button class='submit-v2'>", "x")
    assert out == "button.submit-v2"


def test_repair_null_selector(monkeypatch):
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: (
            lambda p: json.dumps({"selector": None})))
    assert wr._llm_repair_selector("#x", "<html></html>", "x") is None


def test_repair_bad_json(monkeypatch):
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: (lambda p: "not json at all"))
    assert wr._llm_repair_selector("#x", "<html></html>", "x") is None
