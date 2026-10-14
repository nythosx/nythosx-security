import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import pytest

from engine.recon import wayback


def test_is_priority_detects_api():
    assert wayback._is_priority("/api/users") is True
    assert wayback._is_priority("/admin") is True
    assert wayback._is_priority("/.env") is True
    assert wayback._is_priority("/about") is False


def test_harvest_handles_bad_input():
    result = wayback.harvest("")
    assert result is None or isinstance(result, dict)


def test_harvest_disabled(monkeypatch):
    monkeypatch.setattr(wayback, "_cfg", lambda: {"enabled": False})
    assert wayback.harvest("example.com") is None


def test_harvest_with_mocked_sources(monkeypatch):
    wayback_urls = [
        "http://example.com/api/users?page=1",
        "http://example.com/api/orders/42",
        "http://example.com/old-admin",
        "http://example.com/about",
    ]
    cc_urls = [
        "http://example.com/api/v2/users",
        "http://example.com/debug",
    ]
    monkeypatch.setattr(wayback, "_fetch_wayback",
                        lambda d, l, t: list(wayback_urls))
    monkeypatch.setattr(wayback, "_fetch_commoncrawl",
                        lambda d, i, l, t: list(cc_urls) if i ==
                        wayback.COMMONCRAWL_INDEXES[0] else [])
    monkeypatch.setattr(wayback, "_cfg", lambda: {"enabled": True,
                                                    "commoncrawl": True})

    result = wayback.harvest("example.com", limit=100)
    assert result is not None
    paths = result["paths"]
    assert "/api/users" in paths
    assert "/api/orders/42" in paths
    assert "/api/v2/users" in paths
    priority = result["priority_paths"]
    assert "/api/users" in priority
    assert "/about" not in priority
    params = result["params"]
    assert "page" in params
    assert len(result["sources"]) >= 1


def test_harvest_strips_url_to_domain(monkeypatch):
    seen = []

    def _wb(d, l, t):
        seen.append(d)
        return []

    monkeypatch.setattr(wayback, "_fetch_wayback", _wb)
    monkeypatch.setattr(wayback, "_fetch_commoncrawl", lambda *a: [])
    monkeypatch.setattr(wayback, "_cfg", lambda: {"enabled": True,
                                                    "commoncrawl": False})
    wayback.harvest("https://example.com/some/path")
    assert "example.com" in seen


def test_harvest_returns_none_when_empty(monkeypatch):
    monkeypatch.setattr(wayback, "_fetch_wayback", lambda *a: [])
    monkeypatch.setattr(wayback, "_fetch_commoncrawl", lambda *a: [])
    monkeypatch.setattr(wayback, "_cfg", lambda: {"enabled": True,
                                                    "commoncrawl": True})
    assert wayback.harvest("empty.test") is None
