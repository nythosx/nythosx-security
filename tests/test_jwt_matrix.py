from engine import jwt_attacks
from engine.roe_guard import ROEGuard
from tests.testapp.auth_fixture import Fixture


def _guard():
    return ROEGuard(
        roe={"enabled": True, "scope": {
            "in_scope": ["127.0.0.1", "localhost"],
            "out_of_scope": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_paths": [],
        }},
        engine_cfg={"roe": {"enforce_scope": True,
                             "enforce_methods": True}},
    )


def test_alg_none_detected():
    with Fixture() as fx:
        out = jwt_attacks.run_attack_suite(
            fx.base_url + "/jwt/protected",
            fx.real_token,
            roe_guard=_guard(),
            secrets=["wrong1", "wrong2"],
        )
    vuln = [r for r in out["results"] if r["verdict"] == "VULNERABLE"]
    assert any("none" in r["vector"].lower() for r in vuln), (
        "alg:none not flagged; got %r"
        % [(r["vector"], r["verdict"]) for r in out["results"]])


def test_weak_secret_crack_detected():
    with Fixture() as fx:
        out = jwt_attacks.run_attack_suite(
            fx.base_url + "/jwt/protected",
            fx.real_token,
            roe_guard=_guard(),
            secrets=["weaksecret123"],
        )
    weak = [r for r in out["results"]
            if "weak-secret" in r["vector"] and r["verdict"] == "VULNERABLE"]
    assert weak, (
        "weak-secret crack not flagged; got %r"
        % [(r["vector"], r["verdict"]) for r in out["results"]])


def test_kid_traversal_not_falsely_flagged():
    with Fixture() as fx:
        out = jwt_attacks.run_attack_suite(
            fx.base_url + "/jwt/protected",
            fx.real_token,
            roe_guard=_guard(),
            secrets=["wrong"],
        )
    kid = [r for r in out["results"] if "kid-path" in r["vector"]]
    assert kid, "kid-path vectors absent"
    for r in kid:
        assert r["verdict"] != "VULNERABLE", (
            "kid-path falsely flagged on strict fixture")


def test_jku_x5u_probes_present():
    with Fixture() as fx:
        out = jwt_attacks.run_attack_suite(
            fx.base_url + "/jwt/protected",
            fx.real_token,
            roe_guard=_guard(),
            secrets=["wrong"],
        )
    jku = [r for r in out["results"]
           if "jku" in r["vector"].lower() or "x5u" in r["vector"].lower()]
    assert jku, (
        "jku/x5u probes missing; got %r"
        % [r["vector"] for r in out["results"]])


def test_iss_aud_tamper_probes_present():
    with Fixture() as fx:
        out = jwt_attacks.run_attack_suite(
            fx.base_url + "/jwt/protected",
            fx.real_token,
            roe_guard=_guard(),
            secrets=["wrong"],
        )
    iss_aud = [r for r in out["results"]
                if "iss-tamper" in r["vector"] or "aud-tamper" in r["vector"]]
    assert iss_aud, (
        "iss/aud tamper probes missing; got %r"
        % [r["vector"] for r in out["results"]])


def test_duplicate_claim_probes_present():
    with Fixture() as fx:
        out = jwt_attacks.run_attack_suite(
            fx.base_url + "/jwt/protected",
            fx.real_token,
            roe_guard=_guard(),
            secrets=["wrong"],
        )
    dup = [r for r in out["results"] if "dup-claim" in r["vector"]]
    assert dup, (
        "dup-claim probes missing; got %r"
        % [r["vector"] for r in out["results"]])


def test_recon_secrets_derivation():
    secrets = jwt_attacks.derive_secrets_from_recon(
        "http://127.0.0.1:9999",
        roe_guard=None, verify=False, skip_network=True,
    )
    assert isinstance(secrets, list)
    assert len(secrets) >= 1


def test_derive_handles_no_host():
    secrets = jwt_attacks.derive_secrets_from_recon(
        "", roe_guard=None, verify=False, skip_network=True)
    assert isinstance(secrets, list)


def test_invalid_baseline():
    with Fixture() as fx:
        out = jwt_attacks.run_attack_suite(
            fx.base_url + "/jwt/protected",
            "invalid.jwt.token",
            roe_guard=_guard(),
        )
    assert out.get("error") == "invalid JWT format"


def test_summary_counts():
    with Fixture() as fx:
        out = jwt_attacks.run_attack_suite(
            fx.base_url + "/jwt/protected",
            fx.real_token,
            roe_guard=_guard(),
            secrets=["wrong"],
        )
    for k in ("VULNERABLE", "SUSPICIOUS", "PASS", "UNKNOWN"):
        assert k in out["summary"]
