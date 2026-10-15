import pytest

from engine import diffcrawl as dc
from engine.facts import FactStore


class _Allow:
    def check_url(self, url, method="GET"):
        return True


# ---- unit: pure logic ----------------------------------------------------

def test_bounded_substitution_ids_capped():
    ids = dc._bounded_substitution_ids([10], [2])
    assert ids[0] == 2  # other account's known id first
    assert len(ids) <= dc.MAX_REQUESTS_PER_ENDPOINT
    # neighbors within +-2 of own id 10
    assert set(ids) <= {2, 8, 9, 11, 12}


def test_substitute_path_placeholder():
    assert dc._substitute("/api/doc/{id}", 5) == "/api/doc/5"
    assert dc._substitute("/api/doc/1", 5) == "/api/doc/5"


def test_param_signature_order_independent():
    assert dc.endpoint_key("GET", "/x", {"b": 1, "a": 2}) \
        == dc.endpoint_key("get", "/x", {"a": 9, "b": 8})


def test_compute_differentials_flags_and_passes():
    sets = {
        "anon": {
            "GET /api/admin/config []": {"reachable": True,
                                         "path": "/api/admin/config",
                                         "method": "GET"},
            "GET /api/admin/users []": {"reachable": False},
        },
        "admin": {
            "GET /api/admin/config []": {"reachable": True,
                                         "path": "/api/admin/config",
                                         "method": "GET"},
            "GET /api/admin/users []": {"reachable": True,
                                        "path": "/api/admin/users",
                                        "method": "GET"},
        },
        "user_a": {
            "GET /api/admin/config []": {"reachable": True},
            "GET /api/admin/users []": {"reachable": False},
        },
    }
    diffs = dc.compute_differentials(sets)
    kinds = {(d["kind"], d["path"]) for d in diffs}
    assert ("missing_access_control", "/api/admin/config") in kinds
    assert ("authz_enforced", "/api/admin/users") in kinds


def test_build_sessions_always_has_anon():
    sessions = dc.build_sessions(None)
    assert "anon" in sessions
    assert sessions["anon"].cookies == {}


# ---- integration against the local test app ------------------------------

_ENDPOINTS = [
    {"method": "GET", "path": "/api/me"},
    {"method": "GET", "path": "/api/doc/{id}", "id_param": "id"},
    {"method": "GET", "path": "/api/admin/users"},
    {"method": "GET", "path": "/api/admin/config"},
]


def _creds(base):
    return {
        "login": {"url": base + "/login", "type": "json",
                  "username_field": "username",
                  "password_field": "password", "token_path": None},
        "accounts": {
            "user_a": {"username": "user_a", "password": "x",
                       "known_ids": [1, 3]},
            "user_b": {"username": "user_b", "password": "x",
                       "known_ids": [2]},
            "admin": {"username": "admin", "password": "x",
                      "known_ids": [99]},
        },
    }


@pytest.fixture
def app():
    from tests.testapp import start_app
    base, srv = start_app()
    yield base
    srv.shutdown()


def test_idor_candidate_detected(app):
    sessions = dc.build_sessions(_creds(app))
    cands = dc.id_substitution_candidates(app, sessions, _ENDPOINTS,
                                          roe_guard=_Allow())
    cross = [c for c in cands if c["is_cross_account"]]
    assert cross, "user_a should reach user_b's doc by ID substitution"
    assert any(c["substituted_id"] == 2 for c in cross)


def test_differential_flags_broken_authz_and_passes_enforced(app):
    result = dc.scan(app, creds=_creds(app), endpoints=_ENDPOINTS,
                     roe_guard=_Allow(), fact_store=FactStore())
    kinds = {(d["kind"], d["path"]) for d in result["differentials"]}
    assert ("missing_access_control", "/api/admin/config") in kinds
    assert ("authz_enforced", "/api/admin/users") in kinds


def test_scan_emits_idor_fact_and_confirms(app):
    from engine import confirm
    fs = FactStore()
    result = dc.scan(app, creds=_creds(app), endpoints=_ENDPOINTS,
                     roe_guard=_Allow(), fact_store=fs,
                     confirm_fn=confirm.confirm)
    assert fs.get("has_idor_candidate") is True
    assert result["facts_emitted"]
    confirmed = [c for c in result["confirmations"]
                 if c["result"].get("confirmed")]
    assert confirmed, "IDOR candidate should confirm via the confirm gate"
