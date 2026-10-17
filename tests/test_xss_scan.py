import pytest

try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        p.chromium.launch(headless=True).close()
except Exception as e:
    pytest.skip("Playwright chromium not available: %s" % e,
                allow_module_level=True)

from engine import xss
from engine import xss_pack
from tests.testapp.xss_fixture import Fixture


def test_probe_returns_attempts():
    with Fixture() as fx:
        r = xss.probe(fx.base_url + "/body", param="q")
    assert r["attempts"]


def test_analyze_reflection_matches_pack():
    ctx = xss.analyze_reflection('<input value="', "", '"')
    assert ctx in xss_pack.PACK.context_variants


def test_scan_context_aware_smoke():
    with Fixture() as fx:
        r = xss.scan(fx.base_url + "/body", param="q",
                     context="html_body", budget=3)
    assert "verdict" in r
    assert r["verdict"] in ("VULNERABLE", "PASS", "SUSPICIOUS", "UNKNOWN")
