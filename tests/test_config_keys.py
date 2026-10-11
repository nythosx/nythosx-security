import json

from engine import evidence, report, ledger


def _ctx(body):
    return {"steps": [{"step_name": "s", "loop_index": 0, "status": 200,
                       "time_ms": 1.0, "body_hash": "h", "url": "http://t",
                       "error": None, "headers": {}, "body": body}],
            "inputs": {}, "target": "http://t"}


def test_evidence_max_body_size_truncates(tmp_path, monkeypatch):
    monkeypatch.setattr(evidence, "EVIDENCE_DIR", tmp_path)
    big = "A" * 5000
    cfg = {"evidence": {"save_raw_bodies": True, "max_body_size_kb": 1}}  # 1 KB
    path = evidence.save_evidence("p", "http://t", _ctx(big), "PASS",
                                  {"reason": "", "evidence": {}}, engine_cfg=cfg)
    raw = json.loads((__import__("pathlib").Path(path) / "raw.json").read_text())
    assert len(raw[0]["body_preview"]) == 1024


def test_evidence_save_raw_bodies_false(tmp_path, monkeypatch):
    monkeypatch.setattr(evidence, "EVIDENCE_DIR", tmp_path)
    cfg = {"evidence": {"save_raw_bodies": False, "max_body_size_kb": 100}}
    path = evidence.save_evidence("p", "http://t", _ctx("secret body"), "PASS",
                                  {"reason": "", "evidence": {}}, engine_cfg=cfg)
    raw = json.loads((__import__("pathlib").Path(path) / "raw.json").read_text())
    assert raw[0]["body_preview"] == ""


def test_report_severity_threshold_filters(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")
    target = "http://127.0.0.1/api"
    ledger.record_finding("cors-wildcard", target, "VULNERABLE", "high",
                          "cors", "", {}, category="single")
    ledger.record_finding("server-disclosure", target, "VULNERABLE", "low",
                          "server header", "", {}, category="single")

    cfg = {"report": {"severity_threshold": "high"}}
    path = report.generate(target, fmt="md", engine_cfg=cfg)
    text = (tmp_path / "reports" / __import__("os").path.basename(path)).read_text(encoding="utf-8")
    assert "cors-wildcard" in text
    assert "server-disclosure" not in text


def test_report_threshold_info_keeps_all(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")
    target = "http://127.0.0.1/api"
    ledger.record_finding("cors-wildcard", target, "VULNERABLE", "high",
                          "cors", "", {}, category="single")
    ledger.record_finding("server-disclosure", target, "VULNERABLE", "low",
                          "server header", "", {}, category="single")
    cfg = {"report": {"severity_threshold": "info"}}
    path = report.generate(target, fmt="md", engine_cfg=cfg)
    text = (tmp_path / "reports" / __import__("os").path.basename(path)).read_text(encoding="utf-8")
    assert "cors-wildcard" in text
    assert "server-disclosure" in text

def test_new_v2_config_keys_present(monkeypatch, tmp_path):
    from engine import config as cfg
    monkeypatch.setattr(cfg, "CONFIGS", tmp_path)
    (tmp_path / "engine.yaml").write_text("http:\n  timeout_seconds: 5\n")
    data = cfg.load_engine()
    for key in ("baseline", "diff", "scoring", "triage", "waf",
                "iteration", "confirm"):
        assert key in data, "missing default key: " + key
        assert isinstance(data[key], dict), key

def test_new_v2_config_keys_custom(monkeypatch, tmp_path):
    from engine import config as cfg
    monkeypatch.setattr(cfg, "CONFIGS", tmp_path)
    (tmp_path / "engine.yaml").write_text(
        "baseline:\n  enabled: false\n"
        "iteration:\n  max_sweeps: 7\n"
    )
    data = cfg.load_engine()
    assert data["baseline"]["enabled"] is False
    assert data["iteration"]["max_sweeps"] == 7
