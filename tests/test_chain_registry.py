
import re

from engine.chain_engine import ChainOrchestrator
from engine.chain_registry import get_all_chains


_BUILTIN_KEYS = {"target"}

_RECON_FACTS = {
    "framework", "framework_name", "powered_by", "server",
    "api_base", "api_source", "catch_all", "open_ports",
    "js_bundle_count", "api_paths", "js_total_kb",
    "has_login", "has_jwt_hint", "has_graphql_hint",
    "has_ecommerce", "has_coupon", "has_financial",
    "has_admin_paths", "has_ssrf_hint", "has_llm_hint",
    "has_workflow", "has_search", "has_upload",
    "has_graphql", "has_openapi", "has_admin",
    "has_cart", "has_coupon_endpoint",
    "has_jwt_token",
    "sca_requested",
    "has_oauth_hint", "has_websocket_hint", "has_redirect_hint",
    "has_ssti_hint", "has_xml_hint", "has_http2_hint",
}

_CONTEXT_KEYS = {
    "graphql_url", "admin_url", "login_url", "cart_url", "coupon_url",
    "jwt_token", "jwt_token_source", "login_info",
    "sca_path",
    "oauth_auth_endpoint", "websocket_url", "upload_url",
}

_VALID_RESULT_KEYS = {"verdict", "reason", "evidence", "error", "duration_ms"}
_VALID_MODES = {"any", "all", "none"}
_VALID_ON_FAIL = {"next", "abort", None}


def _exported_facts():
    facts = set()
    for chain in get_all_chains():
        for step in chain.get("steps", []):
            for key in (step.get("exports") or {}).keys():
                facts.add(key)
    return facts


def _all_known_keys():
    return _BUILTIN_KEYS | _RECON_FACTS | _CONTEXT_KEYS | _exported_facts()


def test_get_all_chains_returns_list():
    chains = get_all_chains()
    assert isinstance(chains, list)
    assert len(chains) >= 9


def test_chain_ids_unique():
    ids = [c["id"] for c in get_all_chains()]
    assert len(ids) == len(set(ids))


def test_expected_chain_ids_present():
    ids = {c["id"] for c in get_all_chains()}
    expected = {
        "jwt-chain", "graphql-chain", "ssrf-chain", "bizlogic-chain",
        "race-chain", "llm-chain", "xss-chain", "openapi-chain",
        "sca-chain",
    }
    assert expected <= ids


def test_every_chain_has_required_fields():
    for c in get_all_chains():
        assert c.get("id"), c
        assert c.get("name"), c
        assert isinstance(c.get("priority"), int), c["id"]
        assert isinstance(c.get("trigger"), dict), c["id"]
        assert isinstance(c.get("steps"), list), c["id"]
        assert c["steps"], f"{c['id']} has no steps"


def test_every_step_has_unique_id_within_chain():
    for c in get_all_chains():
        ids = [s["id"] for s in c["steps"]]
        assert len(ids) == len(set(ids)), c["id"]


def test_every_step_has_tool():
    for c in get_all_chains():
        for s in c["steps"]:
            assert isinstance(s.get("tool"), str), (c["id"], s.get("id"))
            assert s["tool"], (c["id"], s.get("id"))


def test_every_tool_exists_in_handlers():
    handlers = set(ChainOrchestrator._TOOL_HANDLERS.keys())
    for c in get_all_chains():
        for s in c["steps"]:
            assert s["tool"] in handlers, (
                f"{c['id']}.{s['id']}: tool '{s['tool']}' "
                f"not in {sorted(handlers)}")


def test_every_trigger_mode_valid():
    for c in get_all_chains():
        mode = c["trigger"].get("mode", "any")
        assert mode in _VALID_MODES, c["id"]


def test_every_trigger_has_conditions():
    for c in get_all_chains():
        conds = c["trigger"].get("conditions") or []
        assert conds, c["id"]
        for cond in conds:
            assert cond.get("fact"), c["id"]


def test_every_precondition_mode_valid():
    for c in get_all_chains():
        for s in c["steps"]:
            pre = s.get("precondition")
            if not pre:
                continue
            mode = pre.get("mode", "any")
            assert mode in _VALID_MODES, (c["id"], s["id"])


def test_every_on_fail_valid():
    for c in get_all_chains():
        for s in c["steps"]:
            assert s.get("on_fail") in _VALID_ON_FAIL, (c["id"], s["id"])


def test_every_trigger_fact_producible():
    known = _all_known_keys()
    for c in get_all_chains():
        for cond in c["trigger"].get("conditions") or []:
            fact = cond["fact"]
            assert fact in known, (
                f"{c['id']} trigger references unknown fact '{fact}'")


def test_every_precondition_fact_producible():
    known = _all_known_keys()
    for c in get_all_chains():
        for s in c["steps"]:
            pre = s.get("precondition") or {}
            for cond in pre.get("conditions") or []:
                fact = cond["fact"]
                assert fact in known, (
                    f"{c['id']}.{s['id']} precondition references "
                    f"unknown fact '{fact}'")


def test_every_arg_reference_resolves():
    known = _all_known_keys()
    pat = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")
    for c in get_all_chains():
        for s in c["steps"]:
            for k, v in (s.get("args") or {}).items():
                if not isinstance(v, str):
                    continue
                for m in pat.finditer(v):
                    key = m.group(1)
                    assert key in known, (
                        f"{c['id']}.{s['id']}.{k}: "
                        f"arg references unknown key '{key}'")


def test_every_export_path_valid():
    for c in get_all_chains():
        for s in c["steps"]:
            for ctx_key, path in (s.get("exports") or {}).items():
                assert isinstance(ctx_key, str) and ctx_key, (c["id"], s["id"])
                assert isinstance(path, str) and path, (c["id"], s["id"])
                head = path.split(".", 1)[0]
                assert head in _VALID_RESULT_KEYS, (
                    f"{c['id']}.{s['id']} exports path '{path}' "
                    f"starts with '{head}' (expected one of "
                    f"{sorted(_VALID_RESULT_KEYS)})")


def test_priorities_are_distinct():
    priorities = [c["priority"] for c in get_all_chains()]
    assert len(priorities) == len(set(priorities)), priorities


def test_jwt_chain_has_expected_vectors():
    chain = next(c for c in get_all_chains() if c["id"] == "jwt-chain")
    vectors = []
    for s in chain["steps"]:
        v = (s.get("args") or {}).get("vector")
        if v:
            vectors.append(v)
    assert "alg:none" in vectors
    assert "algorithm-confusion" in vectors
    assert "kid" in vectors
    assert "weak-secret" in vectors


def test_chain_priority_ordering_matches_recon_flow():
    chains = get_all_chains()
    by_id = {c["id"]: c["priority"] for c in chains}
    assert by_id["jwt-chain"] > by_id["graphql-chain"]
    assert by_id["graphql-chain"] > by_id["ssrf-chain"]
    assert by_id["ssrf-chain"] > by_id["bizlogic-chain"]
    assert by_id["bizlogic-chain"] > by_id["race-chain"]
    assert by_id["race-chain"] > by_id["llm-chain"]
    assert by_id["llm-chain"] > by_id["xss-chain"]
    assert by_id["xss-chain"] > by_id["openapi-chain"]
    assert by_id["openapi-chain"] > by_id["sca-chain"]


def test_sca_chain_only_triggers_on_explicit_flag():
    chain = next(c for c in get_all_chains() if c["id"] == "sca-chain")
    conds = chain["trigger"]["conditions"]
    assert len(conds) == 1
    assert conds[0]["fact"] == "sca_requested"
    assert chain["trigger"]["mode"] == "all"


def test_jwt_cracked_secret_exported_from_weak_secret_step():
    chain = next(c for c in get_all_chains() if c["id"] == "jwt-chain")
    weak = next(s for s in chain["steps"] if s["id"] == "weak_secret")
    assert (weak.get("exports") or {}).get("jwt_cracked_secret") == \
        "evidence.secret"


def test_no_chain_references_has_api():
    for c in get_all_chains():
        conds = (c["trigger"] or {}).get("conditions") or []
        for cond in conds:
            assert cond["fact"] != "has_api", (
                f"{c['id']} uses 'has_api' which recon never produces")
