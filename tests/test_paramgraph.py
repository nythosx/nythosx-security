import pytest

from engine import paramgraph as pg
from engine.diff import BaselineSnapshot
from engine.facts import FactStore


def _baseline(body='{"ok": true}', status=200):
    return BaselineSnapshot(status=status, body=body, body_len=len(body),
                            structure=None)


# ---- classify_value ------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (1, "int"),
    (1.5, "float"),
    (True, "bool"),
    ("42", "int"),
    ("3.14", "float"),
    ("true", "bool"),
    ("a@b.com", "email"),
    ("550e8400-e29b-41d4-a716-446655440000", "uuid"),
    ("https://x.y/z", "url"),
    ("report.pdf", "filename"),
    ("hello world", "string"),
    (None, "string"),
])
def test_classify_value(value, expected):
    assert pg.classify_value(value) == expected


def test_classify_value_jwt():
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0."
           "abc123def456")
    assert pg.classify_value(jwt) == "jwt"


# ---- classification logic (mocked HTTP) ----------------------------------

def _runner_for(accept):
    """accept(label) -> status code the mock endpoint returns."""
    def runner(label, value):
        return {"status": accept(label), "body": "{}",
                "content_type": "application/json"}
    return runner


def test_strict_numeric_classification():
    def accept(label):
        return 200 if label in ("int", "float") else 400
    node = pg.infer_param_type("id", _runner_for(accept), _baseline())
    assert node.classification == pg.CLASS_STRICT_NUMERIC
    assert pg.injection_families_for(node) == ["sqli"]


def test_loose_string_classification():
    node = pg.infer_param_type("q", _runner_for(lambda l: 200), _baseline())
    assert node.classification == pg.CLASS_LOOSE_STRING
    assert set(pg.injection_families_for(node)) == {"sqli", "ssti", "xss",
                                                    "crlf"}


def test_container_typed_classification():
    def accept(label):
        return 200 if label in ("array", "object") else 400
    node = pg.infer_param_type("settings", _runner_for(accept), _baseline())
    assert node.classification == pg.CLASS_CONTAINER_TYPED
    assert set(pg.injection_families_for(node)) == {"nosql",
                                                    "mass_assignment"}


def test_unknown_when_all_rejected():
    node = pg.infer_param_type("x", _runner_for(lambda l: 400), _baseline())
    assert node.classification == pg.CLASS_UNKNOWN
    assert pg.injection_families_for(node) == []


def test_arithmetic_injection_candidate():
    calls = {"n": 0}

    def arith(value):
        # "1" and "2-1" both return the identical body -> server evaluated.
        return {"status": 200, "body": '{"id": 1, "name": "x"}',
                "content_type": "application/json"}

    def accept(label):
        return 200 if label in ("int", "float") else 400
    node = pg.infer_param_type("id", _runner_for(accept), _baseline(),
                               arithmetic_runner=arith)
    assert node.classification == pg.CLASS_STRICT_NUMERIC
    assert node.arithmetic_injection is True


def test_arithmetic_injection_not_candidate_when_rejected():
    def arith(value):
        if value == "2-1":
            return {"status": 400, "body": "{}"}
        return {"status": 200, "body": "{}"}

    def accept(label):
        return 200 if label in ("int", "float") else 400
    node = pg.infer_param_type("id", _runner_for(accept), _baseline(),
                               arithmetic_runner=arith)
    assert node.arithmetic_injection is False


def test_probe_runner_error_is_recorded():
    def runner(label, value):
        raise ConnectionError("down")
    node = pg.infer_param_type("x", runner, _baseline())
    assert node.classification == pg.CLASS_UNKNOWN
    assert all(p.error for p in node.probes)


# ---- fact store integration ----------------------------------------------

def test_record_param_node_emits_family_facts():
    fs = FactStore()

    def accept(label):
        return 200 if label in ("array", "object") else 400
    node = pg.infer_param_type("settings", _runner_for(accept), _baseline())
    emitted = pg.record_param_node(fs, "/api/profile", node)
    assert "has_mass_assignment_param" in emitted
    assert "has_nosql_param" in emitted
    assert fs.get(pg.fact_key("/api/profile", "settings"))["classification"] \
        == pg.CLASS_CONTAINER_TYPED
    assert fs.get("has_container_param") is True


def test_node_as_dict_roundtrip():
    node = pg.infer_param_type("q", _runner_for(lambda l: 200), _baseline())
    d = node.as_dict()
    assert d["name"] == "q"
    assert d["classification"] == pg.CLASS_LOOSE_STRING
    assert isinstance(d["probes"], list) and len(d["probes"]) == 6


# ---- integration against the local test app ------------------------------

def _rank_ids(fact_store):
    from engine import scoring
    from engine.chain_registry import get_all_chains
    return [c["id"] for c in scoring.rank_chains(get_all_chains(), fact_store)]


def test_integration_routes_each_endpoint_to_correct_chain(monkeypatch):
    from engine.config import load_engine
    from tests.testapp import start_app
    from engine import http as _http

    base, srv = start_app()
    try:
        client = _http.Client(follow_redirects=False)
        try:
            # strict numeric endpoint
            runner = pg.make_http_probe_runner(client, base + "/api/item",
                                               "id", method="GET")
            node = pg.infer_param_type("id", runner)
            assert node.classification == pg.CLASS_STRICT_NUMERIC
            fs = FactStore()
            pg.record_param_node(fs, "/api/item", node)
            assert "blind-sqli-chain" in _rank_ids(fs)

            # loose string endpoint
            runner = pg.make_http_probe_runner(client, base + "/api/search",
                                               "q", method="GET")
            node = pg.infer_param_type("q", runner)
            assert node.classification == pg.CLASS_LOOSE_STRING
            fs = FactStore()
            pg.record_param_node(fs, "/api/search", node)
            ids = _rank_ids(fs)
            assert "xss-chain" in ids and "blind-sqli-chain" in ids

            # mass-assignment endpoint (JSON body, container-typed)
            runner = pg.make_http_probe_runner(client, base + "/api/profile",
                                               "settings", method="POST",
                                               location="json")
            node = pg.infer_param_type("settings", runner)
            assert node.classification == pg.CLASS_CONTAINER_TYPED
            fs = FactStore()
            pg.record_param_node(fs, "/api/profile", node)
            ids = _rank_ids(fs)
            assert "bizlogic-chain" in ids
            assert "injection-family-chain" in ids
        finally:
            client.close()
    finally:
        srv.shutdown()
