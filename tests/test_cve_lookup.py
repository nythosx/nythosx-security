import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import pytest

from engine import cve_lookup


def test_normalize_product_basic():
    assert cve_lookup._normalize_product("nginx") == "nginx"
    assert cve_lookup._normalize_product("NGINX") == "nginx"


def test_normalize_product_strips_version():
    assert cve_lookup._normalize_product("nginx/1.18.0") == "nginx_1_18_0"


def test_normalize_product_handles_empty():
    assert cve_lookup._normalize_product("") == ""
    assert cve_lookup._normalize_product(None) == ""


def test_normalize_version_basic():
    assert cve_lookup._normalize_version("1.18.0") == "1.18.0"


def test_normalize_version_truncates_suffix():
    assert cve_lookup._normalize_version("1.18.0 (Ubuntu)") == "1.18.0"
    assert cve_lookup._normalize_version("8.1.2-1ubuntu2") == "8.1.2"


def test_normalize_version_empty():
    assert cve_lookup._normalize_version("") == ""
    assert cve_lookup._normalize_version(None) == ""


def test_summarize_empty():
    assert cve_lookup.summarize([]) == {
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}


def test_summarize_counts():
    hits = [
        {"severity": "critical"}, {"severity": "critical"},
        {"severity": "high"}, {"severity": "medium"},
        {"severity": "low"}, {"severity": "unknown"},
    ]
    s = cve_lookup.summarize(hits)
    assert s["total"] == 6
    assert s["critical"] == 2
    assert s["high"] == 1
    assert s["medium"] == 1
    assert s["low"] == 1


def test_lookup_unknown_product_returns_empty(monkeypatch):
    monkeypatch.setattr(cve_lookup, "_cfg", lambda: {"enabled": True})
    assert cve_lookup.lookup("randomproduct", "1.0") == []


def test_lookup_disabled_returns_empty(monkeypatch):
    monkeypatch.setattr(cve_lookup, "_cfg", lambda: {"enabled": False})
    assert cve_lookup.lookup("nginx", "1.18.0") == []


def test_lookup_missing_version_returns_empty(monkeypatch):
    monkeypatch.setattr(cve_lookup, "_cfg", lambda: {"enabled": True})
    assert cve_lookup.lookup("nginx", "") == []


def test_lookup_offline_returns_empty(monkeypatch):
    import httpx

    class _Boom:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **k):
            raise httpx.ConnectError("offline")

    monkeypatch.setattr(httpx, "Client", _Boom)
    monkeypatch.setattr(cve_lookup, "_cfg", lambda: {
        "enabled": True, "timeout_seconds": 1,
        "nvd_api_key_env": "NVD_API_KEY",
    })
    cve_lookup._lookup_cached.cache_clear()
    assert cve_lookup.lookup("nginx", "1.18.0") == []


def test_lookup_parses_nvd_response(monkeypatch):
    import httpx

    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-23017",
                    "published": "2021-06-01",
                    "descriptions": [{"lang": "en", "value": "NGINX resolver overflow"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseSeverity": "HIGH"}}
                        ],
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-2019-20372",
                    "published": "2020-01-15",
                    "descriptions": [{"lang": "en", "value": "Request smuggling"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseSeverity": "MEDIUM"}}
                        ],
                    },
                }
            },
        ]
    }

    class _OkResp:
        status_code = 200

        def json(self):
            return payload

    class _Client:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, params=None):
            return _OkResp()

    monkeypatch.setattr(httpx, "Client", _Client)
    monkeypatch.setattr(cve_lookup, "_cfg", lambda: {
        "enabled": True, "timeout_seconds": 1,
        "nvd_api_key_env": "NVD_API_KEY",
    })
    cve_lookup._lookup_cached.cache_clear()
    hits = cve_lookup.lookup("nginx", "1.18.0")
    ids = {h["id"] for h in hits}
    assert "CVE-2021-23017" in ids
    assert "CVE-2019-20372" in ids
    for h in hits:
        assert h["severity"] in ("high", "medium")


def test_cpe_overrides(monkeypatch):
    monkeypatch.setattr(cve_lookup, "_cfg", lambda: {
        "enabled": True, "timeout_seconds": 1,
        "cpe_overrides": {"custom": ["vendor", "product"]},
    })
    calls = []
    original = cve_lookup._lookup_cached

    def _spy(vendor, product, version, api_key, timeout):
        calls.append((vendor, product))
        return ()

    monkeypatch.setattr(cve_lookup, "_lookup_cached", _spy)
    cve_lookup.lookup("custom", "1.0")
    assert ("vendor", "product") in calls
