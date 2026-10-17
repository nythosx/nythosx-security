import json
import tempfile
from pathlib import Path
from engine import program_memory as pm

def test_waf_bypass_tracking():
    with tempfile.TemporaryDirectory() as tmpdir:
        pm.WAF_FILE = Path(tmpdir) / "waf.json"
        pm.record_waf_bypass("cloudflare", "url_double", success=True)
        pm.record_waf_bypass("cloudflare", "url_double", success=True)
        pm.record_waf_bypass("cloudflare", "url_single", success=False)

        bypasses = pm.get_waf_bypasses("cloudflare")
        assert "url_double" in bypasses
        assert bypasses[0] == "url_double"  # Highest success rate

def test_rejection_learning():
    with tempfile.TemporaryDirectory() as tmpdir:
        pm.REJECTIONS_FILE = Path(tmpdir) / "rej.json"
        assert pm.is_rejected("test-pattern") is False
        pm.record_rejection("test-pattern")
        pm.record_rejection("test-pattern")
        assert pm.is_rejected("test-pattern") is False
        pm.record_rejection("test-pattern")
        assert pm.is_rejected("test-pattern") is True  # threshold=3

def test_ev_stats_tracking():
    with tempfile.TemporaryDirectory() as tmpdir:
        pm.EV_STATS_FILE = Path(tmpdir) / "ev.json"
        pm.record_ev_stat("jwt-chain", "credential_access", "laravel", hit=True)
        pm.record_ev_stat("jwt-chain", "credential_access", "laravel", hit=False)

        stats = pm.get_ev_stats("credential_access", "laravel")
        assert stats["attempts"] == 2
        assert stats["hits"] == 1
