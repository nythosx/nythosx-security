from engine.diff import BaselineSnapshot, SemanticDiff, build_structure

def _baseline(status=200, body='{"id":1,"name":"x"}', timing=100.0):
    snap = BaselineSnapshot(
        url="http://t/x", method="GET", status=status, body=body,
        body_len=len(body),
        timing_samples=[timing * 0.95, timing, timing * 1.05],
    )
    snap.structure = build_structure(body, "application/json")
    snap.header_names = {"content-type", "server"}
    return snap

def test_identical_has_low_signal():
    diff = SemanticDiff()
    b = _baseline()
    c = {"status": 200, "body": b.body, "time_ms": 100.0,
         "headers": {"content-type": "application/json", "server": "nginx"}}
    r = diff.compare(b, c)
    assert r.signal_strength < 0.3

def test_status_shift_raises_signal():
    diff = SemanticDiff()
    b = _baseline()
    c = {"status": 500, "body": b.body, "time_ms": 100.0,
         "headers": {"content-type": "application/json", "server": "nginx"}}
    r = diff.compare(b, c)
    assert r.signal_strength >= 0.3

def test_marker_reflection_sets_high_signal():
    diff = SemanticDiff()
    b = _baseline()
    c = {"status": 200, "body": '{"id":1,"name":"MARKER123"}',
         "time_ms": 100.0,
         "headers": {"content-type": "application/json", "server": "nginx"}}
    r = diff.compare(b, c, marker="MARKER123")
    assert r.marker_reflected is True
    assert r.signal_strength >= 0.8

def test_structural_delta_detected():
    diff = SemanticDiff()
    b = _baseline(body='{"id":1,"name":"x"}')
    c = {"status": 200, "body": '{"id":1,"other":"y","extra":"z"}',
         "time_ms": 100.0,
         "headers": {"content-type": "application/json", "server": "nginx"}}
    r = diff.compare(b, c)
    assert r.structural_delta > 0.0

def test_timing_zscore_high():
    diff = SemanticDiff()
    b = _baseline(timing=100.0)
    c = {"status": 200, "body": b.body, "time_ms": 5000.0,
         "headers": {"content-type": "application/json", "server": "nginx"}}
    r = diff.compare(b, c)
    assert r.timing_zscore > 0.0

def test_build_structure_json():
    s = build_structure('{"a":1,"b":"x"}', "application/json")
    assert isinstance(s, dict)
    assert s.get("a") == "int"
    assert s.get("b") == "str"

def test_build_structure_html():
    s = build_structure("<html><body><p>x</p></body></html>", "text/html")
    assert isinstance(s, list)
    assert "html" in s

def test_build_structure_unknown():
    assert build_structure("plain text", "text/plain") is None
