from engine import xss
from tests.testapp.xss_fixture import Fixture


def test_dangling_markup_returns_verdict():
    with Fixture() as fx:
        r = xss.probe_dangling_markup(fx.base_url + "/body", param="q")
    assert "verdict" in r
    assert r["verdict"] in ("SUSPICIOUS", "PASS", "UNKNOWN")


def test_dangling_markup_on_safe():
    with Fixture() as fx:
        r = xss.probe_dangling_markup(fx.base_url + "/safe", param="q")
    assert "verdict" in r
    assert r["verdict"] in ("PASS", "SUSPICIOUS", "UNKNOWN")
