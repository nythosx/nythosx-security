from engine import narrator


def test_unknown_event_returns_none():
    assert narrator.narrate("does_not_exist", {}) is None


def test_none_data_is_safe():
    assert narrator.narrate("phase", None) is None
    r = narrator.narrate("framework", None)
    assert r is not None
    assert r["type"] == "obs"


def test_phase_running():
    r = narrator.narrate("phase", {"name": "preflight", "status": "running"})
    assert r["type"] == "action"
    assert "responds" in r["text"]


def test_phase_done():
    r = narrator.narrate("phase", {"name": "preflight", "status": "done"})
    assert r["type"] == "pass"


def test_phase_unknown_status_returns_none():
    r = narrator.narrate("phase", {"name": "preflight", "status": "bogus"})
    assert r is None


def test_phase_unknown_name_returns_none():
    r = narrator.narrate("phase", {"name": "nope", "status": "running"})
    assert r is None


def test_framework_high_score_is_pass():
    r = narrator.narrate("framework", {"id": "express", "name": "Express", "score": 9})
    assert r["type"] == "pass"
    assert "Express" in r["text"]


def test_framework_low_score_is_obs():
    r = narrator.narrate("framework", {"id": "generic", "name": "Generic", "score": 0})
    assert r["type"] == "obs"


def test_framework_includes_evidence():
    r = narrator.narrate("framework", {
        "id": "express", "name": "Express", "score": 9,
        "evidence": ["header server=X", "cookie connect.sid"],
    })
    assert r["detail"]
    assert "header" in r["detail"]


def test_api_base_js_source():
    r = narrator.narrate("api_base", {
        "url": "https://x/api/v1", "source": "js-bundle", "ports": [],
    })
    assert r["type"] == "pass"
    assert "JavaScript" in r["text"]


def test_api_base_portscan():
    r = narrator.narrate("api_base", {
        "url": "https://x/api", "source": "portscan:https:8443", "ports": [8443],
    })
    assert "port scan" in r["text"]


def test_js_done():
    r = narrator.narrate("js_done", {"count": 7, "size_kb": 842, "paths": 24})
    assert r["type"] == "obs"
    assert "7" in r["text"]
    assert "24" in r["text"]


def test_login_ok():
    r = narrator.narrate("login", {"ok": True, "token": "abc123def456"})
    assert r["type"] == "pass"


def test_login_failed():
    r = narrator.narrate("login", {"ok": False})
    assert r["type"] == "obs"
    assert "No login" in r["text"]


def test_pattern_start():
    r = narrator.narrate("pattern_start", {"id": "security-headers-missing"})
    assert r["type"] == "action"
    assert "security-headers-missing" in r["text"]


def test_pattern_done_vulnerable():
    r = narrator.narrate("pattern_done", {
        "id": "env-file-exposure",
        "verdict": "VULNERABLE",
        "reason": "APP_KEY leaked",
    })
    assert r["type"] == "vuln"


def test_pattern_done_suspicious():
    r = narrator.narrate("pattern_done", {
        "id": "cors-wildcard", "verdict": "SUSPICIOUS", "reason": "reflected origin",
    })
    assert r["type"] == "susp"


def test_pattern_done_pass():
    r = narrator.narrate("pattern_done", {
        "id": "security-headers-missing", "verdict": "PASS", "reason": "all present",
    })
    assert r["type"] == "pass"


def test_pattern_done_unknown():
    r = narrator.narrate("pattern_done", {
        "id": "race-condition", "verdict": "UNKNOWN", "reason": "unreachable",
    })
    assert r["type"] == "obs"


def test_pattern_done_with_evidence():
    r = narrator.narrate("pattern_done", {
        "id": "jwt-weak-secret",
        "verdict": "VULNERABLE",
        "reason": "secret cracked",
        "payload": "word=secret",
        "request": "POST /api/v1/me",
        "response": "HTTP 200",
    })
    assert r["detail"]
    assert "secret" in r["detail"]
    assert "POST" in r["detail"]


def test_pattern_done_evidence_from_dict():
    r = narrator.narrate("pattern_done", {
        "id": "x", "verdict": "VULNERABLE", "reason": "y",
        "evidence": {"payload": "inside-evidence"},
    })
    assert "inside-evidence" in r["detail"]


def test_pattern_done_evidence_sent_fallback():
    r = narrator.narrate("pattern_done", {
        "id": "x", "verdict": "VULNERABLE", "reason": "y",
        "evidence": {"sent": "sent-value"},
    })
    assert "sent-value" in r["detail"]


def test_html_escaping_pattern_id():
    r = narrator.narrate("pattern_done", {
        "id": "<script>alert(1)</script>",
        "verdict": "PASS",
        "reason": "nothing",
    })
    assert "<script>" not in r["text"]
    assert "&lt;script&gt;" in r["text"]


def test_html_escaping_framework_name():
    r = narrator.narrate("framework", {
        "id": "x", "name": "<img src=x onerror=alert(1)>", "score": 99,
    })
    assert "<img" not in r["text"]
    assert "&lt;img" in r["text"]


def test_html_escaping_reason():
    r = narrator.narrate("pattern_done", {
        "id": "x", "verdict": "VULNERABLE",
        "reason": "<b>raw</b>",
    })
    assert "<b>raw</b>" not in r["text"]
    assert "&lt;b&gt;raw&lt;/b&gt;" in r["text"]


def test_summary_empty():
    s = narrator.summarize({"target": "http://x", "counts": {}, "findings": []})
    assert s["target"] == "http://x"
    assert s["bullets"] == []
    assert s["closing"]
    assert "held up" in s["closing"]


def test_summary_with_vulns():
    s = narrator.summarize({
        "target": "http://x",
        "counts": {"VULNERABLE": 1, "SUSPICIOUS": 0, "PASS": 0},
        "findings": [
            {"pattern_id": "env-file-exposure", "verdict": "VULNERABLE",
             "reason": "env leaked", "why": {"impact": "full compromise"}},
        ],
    })
    assert any("CRITICAL" in b["html"] for b in s["bullets"])
    assert "real" in s["closing"].lower()


def test_summary_with_suspicious():
    s = narrator.summarize({
        "target": "http://x",
        "counts": {"VULNERABLE": 0, "SUSPICIOUS": 1},
        "findings": [
            {"pattern_id": "ssrf", "verdict": "SUSPICIOUS", "reason": "timing"},
        ],
    })
    assert any("SUSPICIOUS" in b["html"] for b in s["bullets"])
    assert "human" in s["closing"].lower()


def test_summary_with_pass():
    s = narrator.summarize({
        "target": "http://x",
        "counts": {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 3},
        "findings": [
            {"pattern_id": "security-headers-missing", "verdict": "PASS"},
            {"pattern_id": "cors-wildcard", "verdict": "PASS"},
            {"pattern_id": "env-file-exposure", "verdict": "PASS"},
        ],
    })
    assert any("passed" in b["html"].lower() for b in s["bullets"])


def test_summary_uses_entered_url_fallback():
    s = narrator.summarize({"entered_url": "http://y", "counts": {}, "findings": []})
    assert s["target"] == "http://y"


def test_summary_skips_non_vuln_susp():
    s = narrator.summarize({
        "target": "http://x",
        "counts": {"PASS": 1},
        "findings": [
            {"pattern_id": "a", "verdict": "PASS"},
            {"pattern_id": "b", "verdict": "UNKNOWN"},
        ],
    })
    assert len(s["bullets"]) == 1
    assert "passed" in s["bullets"][0]["html"].lower()


def test_summary_danger_class_on_vuln():
    s = narrator.summarize({
        "target": "http://x",
        "counts": {"VULNERABLE": 1},
        "findings": [
            {"pattern_id": "jwt", "verdict": "VULNERABLE", "reason": "bypass"},
        ],
    })
    assert any(b["class"] == "danger" for b in s["bullets"])


def test_narrate_returns_none_on_internal_error():
    r = narrator.narrate("phase", {"name": object(), "status": "running"})
    assert r is None


def test_summarize_handles_missing_fields():
    s = narrator.summarize({})
    assert "target" in s
    assert "bullets" in s
    assert "closing" in s
