import pytest

from engine import drupalchain as dc
from engine import capgraph as cg
from engine.facts import FactStore


@pytest.fixture
def app():
    from tests.testapp.drupal_mimic import start_drupal_mimic
    base, srv = start_drupal_mimic()
    yield base
    srv.shutdown()


def _run(app):
    fs = FactStore()
    res = dc.run_all(app, fact_store=fs)
    return res, fs


# ---- all five surfaces flagged with correct severities -------------------

def test_five_surfaces_flagged(app):
    res, _ = _run(app)
    by_type = {}
    for f in res["findings"]:
        if f.get("verdict") == "VULNERABLE":
            by_type[f["type"]] = f["severity"]
    assert by_type.get("user_enumeration") == "high"          # admin email
    assert by_type.get("broken_access_control") == "high"     # jsonapi
    assert by_type.get("maintenance_endpoint_exposed") == "critical"  # update.php
    assert by_type.get("sensitive_file_exposure") == "high"   # storage .sql
    assert by_type.get("version_disclosure") == "info"        # CHANGELOG


# ---- framework fact upgraded from Generic to drupal <version> ------------

def test_framework_fact_upgraded(app):
    res, fs = _run(app)
    assert res["framework_version"] == "9.4.8"
    assert fs.get("framework") == "drupal 9.4.8"


# ---- capability chain composes config_disclosure -> obtain_token -> write_data

def test_capability_chain_composes(app):
    res, _ = _run(app)
    chains = cg.analyze(res["confirmed"])
    assert chains, "expected a composed capability chain"
    hit = [c for c in chains if c["path"][-1] == "write_data"
           and "obtain_token" in c["path"]]
    assert hit, "expected config_disclosure -> obtain_token -> write_data"
    ids = set(hit[0]["finding_ids"])
    assert "config_disclosure" in ids and "idor" in ids


# ---- request counts stay within per-chain caps ---------------------------

def test_request_caps(app):
    send = dc.make_send(app)
    soft = dc.soft404_fingerprint(send)
    u = dc.user_idor_chain(send, soft404=soft)
    assert u["requests"] <= dc.USER_IDOR_MAX
    fsr = dc.file_storage_chain(send, soft404=soft)
    assert fsr["requests"] <= dc.FILE_STORAGE_MAX


# ---- rest/session/token is NOT flagged (expected Drupal behaviour) -------

def test_rest_session_token_not_flagged(app):
    send = dc.make_send(app)
    soft = dc.soft404_fingerprint(send)
    rest = dc.rest_exposure_chain(send, soft404=soft)
    types = {f["type"] for f in rest["findings"]}
    assert "rest_session_token" not in types
    assert any(n["type"] == "rest_session_token" for n in rest["notes"])


# ---- org recon derives email patterns (informational, no probing) --------

def test_org_recon_email_patterns(app):
    send = dc.make_send(app)
    org = dc.org_recon_chain(send)
    assert org["org_email_patterns"]
    assert any(p.endswith("@") for p in org["org_email_patterns"])


# ---- negative-control gate keeps sound findings confirmed ----------------

def test_config_disclosure_confirmed_not_suppressed(app):
    res, _ = _run(app)
    cfg = [f for f in res["findings"] if f["type"] == "config_disclosure"]
    assert cfg and cfg[0]["verdict"] == "VULNERABLE"
    assert cfg[0].get("confirmation_status") == "confirmed"


# ---- soft-404 fingerprint prevents false positives -----------------------

def test_soft404_suppresses_nonexistent(app):
    send = dc.make_send(app)
    soft = dc.soft404_fingerprint(send)
    # a clearly non-existent maintenance path must not be flagged
    resp = send("GET", "/core/update.php")
    assert resp["status"] in (403, 404)


# ---- unit branches with fake transports (no network) ---------------------

def _fake(routes, default=(404, "")):
    def send(method, path, headers=None, params=None):
        for key, (status, body) in routes.items():
            if path == key or path.startswith(key):
                return {"status": status, "body": body, "headers": {},
                        "url": path}
        return {"status": default[0], "body": default[1], "headers": {},
                "url": path}
    return send


def test_make_send_roe_block():
    from engine.roe_guard import ROEViolation

    class _Deny:
        def check_url(self, url, method="GET"):
            raise ROEViolation("nope")
    send = dc.make_send("http://127.0.0.1:1", client=object(),
                        roe_guard=_Deny())
    resp = send("GET", "/user/1")
    assert resp.get("roe_block") is True


def test_config_env_exposure_branch():
    send = _fake({"/.env": (200, "DB_PASSWORD=secret123")})
    res = dc.config_exposure_chain(send)
    assert any(f["type"] == "config_disclosure" for f in res["findings"])


def test_views_ajax_with_params_dumps_data():
    send = _fake({"/views/ajax": (200, '{"data":[' + "x" * 300 + ']}')})
    res = dc.views_ajax_chain(send, params={"view_name": "content"})
    assert any(f["type"] == "unauthenticated_data_disclosure"
               for f in res["findings"])


def test_org_recon_no_names():
    send = _fake({}, default=(404, ""))
    res = dc.org_recon_chain(send)
    assert res["org_email_patterns"] == []


def test_apply_gate_suppresses_when_benign_path_reachable():
    from engine.oracles.controls import OracleGate
    # a transport where EVERY path (incl. the benign control) is reachable
    send = _fake({"/": (200, "ok")}, default=(200, "ok"))
    gate = OracleGate()
    finding = {"type": "maintenance_endpoint_exposed", "verdict": "VULNERABLE",
               "severity": "critical", "reason": "x",
               "negative_control_path": "/zzz-nonexistent-sentinel-4041x"}
    out = dc.chains._apply_gate(finding, send, gate)
    assert out["verdict"] == "PASS"
    assert out["confirmation_status"] == "tool_unsound"


def test_run_all_without_fact_store(app):
    res = dc.run_all(app, fact_store=None)
    assert res["confirmed"]
    assert res["requests"] > 0
