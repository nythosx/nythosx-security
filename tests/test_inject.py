import json

import pytest

from engine.inject import structural, parserdiff, graphqlx, headersurf


# ---- A1 structural -------------------------------------------------------

def test_generate_mutations_kinds_and_cap():
    muts = structural.generate_mutations({"role": "user", "id": 5})
    kinds = {m.kind for m in muts}
    assert {"duplicate_key", "type_juggle", "deep_nesting",
            "proto_pollution"} <= kinds
    assert len(muts) <= structural.MAX_MUTATIONS


def test_generate_mutations_dedupe():
    muts = structural.generate_mutations(
        {"id": 1}, dedupe_against=[{"kind": "proto_pollution"}])
    assert all(m.kind != "proto_pollution" for m in muts)


def test_deep_nesting_capped():
    muts = structural.generate_mutations({"id": 1})
    deep = [m for m in muts if m.kind == "deep_nesting"][0]
    # depth must not exceed the cap (count nested "a" keys)
    assert deep.raw_body.count('"a"') <= structural.MAX_NESTING_DEPTH


def test_structural_scan_flags_divergence():
    base = {"role": "user", "id": 5}

    def send(method, url, raw_body, content_type):
        # echo the body back so dup-key "admin" and "polluted" surface
        return {"status": 200, "body": raw_body,
                "content_type": "application/json"}
    res = structural.scan("http://t/api", base, send)
    assert res["verdict"] == "SUSPICIOUS"
    kinds = {f["kind"] for f in res["findings"]
             if f.get("verdict") == "SUSPICIOUS"}
    assert "duplicate_key" in kinds and "proto_pollution" in kinds


# ---- A2 parserdiff -------------------------------------------------------

def test_parserdiff_variants_capped():
    vs = parserdiff.build_variants({"a": 1}, "application/json")
    assert len(vs) <= parserdiff.MAX_VARIANTS
    labels = {v[0] for v in vs}
    assert "json_as_form" in labels and "multipart_dup_filename" in labels


def test_parserdiff_flags_divergence():
    def send(method, url, body, content_type, extra):
        if content_type == "application/x-www-form-urlencoded":
            return {"status": 500, "body": "err", "content_type": "text/plain"}
        return {"status": 200, "body": '{"ok":true}',
                "content_type": "application/json"}
    res = parserdiff.scan("http://t/api", {"a": 1}, send)
    assert res["verdict"] == "SUSPICIOUS"
    assert any(f.get("variant") == "json_as_form"
               and f["verdict"] == "SUSPICIOUS" for f in res["findings"])


# ---- A3 graphqlx ---------------------------------------------------------

def test_extract_field_suggestions():
    err = 'Cannot query field "scret". Did you mean "secret"?'
    fields = graphqlx.extract_field_suggestions(err)
    assert "secret" in fields


def test_alias_batch_query_capped():
    q = graphqlx.alias_batch_query("x", 10)
    assert q.count(":x") <= graphqlx.MAX_ALIASES


def test_graphqlx_scan_detects_surfaces():
    def post(url, query):
        if "__schema" in query:
            return {"status": 200,
                    "body": json.dumps({"data": {"__schema":
                                        {"types": [{"name": "User"}]}}})}
        if "mutation" in query:
            return {"status": 200,
                    "body": json.dumps({"data": {"__typename": "Mutation"}})}
        if "zzz_nope_field" in query:
            return {"status": 200,
                    "body": 'Did you mean "hiddenField"?'}
        return {"status": 200, "body": json.dumps({"data": {}})}
    res = graphqlx.scan("http://t/graphql", post, read_only=True)
    assert res["verdict"] == "VULNERABLE"
    types = {f["type"] for f in res["findings"]}
    assert "graphql_introspection_exposed" in types
    assert "graphql_mutation_exposed" in types


# ---- A4 headersurf -------------------------------------------------------

def test_headersurf_flags_forbidden_bypass():
    def send(method, url, headers):
        if headers.get("X-Original-URL"):
            return {"status": 200, "body": "admin panel", "headers": {}}
        return {"status": 403, "body": "forbidden", "headers": {}}
    res = headersurf.scan("http://t/admin", send)
    assert res["verdict"] == "SUSPICIOUS"
    assert any("X-Original-URL" in f["header"] for f in res["findings"])


def test_headersurf_no_bypass_is_pass():
    def send(method, url, headers):
        return {"status": 200, "body": "same", "headers": {}}
    res = headersurf.scan("http://t/x", send)
    assert res["verdict"] == "PASS"


def test_headersurf_baseline_failure():
    def send(method, url, headers):
        raise ConnectionError("down")
    res = headersurf.scan("http://t/x", send)
    assert res["verdict"] == "UNKNOWN"


def test_headersurf_per_header_error_and_explicit_baseline():
    calls = {"n": 0}

    def send(method, url, headers):
        calls["n"] += 1
        raise TimeoutError("slow")
    base = {"status": 403, "body": "forbidden", "headers": {}}
    res = headersurf.scan("http://t/admin", send, baseline_resp=base)
    assert res["verdict"] == "PASS"
    assert all(f["verdict"] == "UNKNOWN" for f in res["evidence"]["headers"])


# ---- extra structural branches -------------------------------------------

def test_structural_duplicate_rejected_and_proto_pass():
    base = {"role": "user", "id": 5}

    def send(method, url, raw_body, content_type):
        if '"role": "user", "role": "admin"' in raw_body \
                or '"role": "admin"' in raw_body and raw_body.count("role") == 2:
            return {"status": 400, "body": "bad", "content_type": "text/plain"}
        if "polluted" in raw_body:
            return {"status": 200, "body": "{}",
                    "content_type": "application/json"}
        return {"status": 200, "body": raw_body,
                "content_type": "application/json"}
    res = structural.scan("http://t/api", base, send)
    kinds = {f["kind"]: f for f in res["findings"]}
    assert kinds["duplicate_key"]["verdict"] == "PASS"
    assert kinds["proto_pollution"]["verdict"] == "PASS"


def test_structural_send_exception_is_unknown():
    def send(method, url, raw_body, content_type):
        if raw_body and "nested" in raw_body:
            raise ConnectionError("x")
        return {"status": 200, "body": raw_body or "{}",
                "content_type": "application/json"}
    res = structural.scan("http://t/api", {"id": 1}, send)
    assert any(f.get("verdict") == "UNKNOWN" for f in res["findings"])


def test_structural_baseline_failure():
    def send(method, url, raw_body, content_type):
        raise ConnectionError("down")
    res = structural.scan("http://t/api", {"id": 1}, send)
    assert res["verdict"] == "UNKNOWN"


# ---- extra parserdiff branches -------------------------------------------

def test_parserdiff_xml_variants():
    vs = parserdiff.build_variants("<x>1</x>", "text/xml")
    labels = {v[0] for v in vs}
    assert "xml_text" in labels and "xml_app" in labels


def test_parserdiff_baseline_and_variant_errors():
    def bad_baseline(method, url, body, content_type, extra):
        raise ConnectionError("down")
    assert parserdiff.scan("http://t", {"a": 1},
                           bad_baseline)["verdict"] == "UNKNOWN"

    def flaky(method, url, body, content_type, extra):
        if content_type == "application/json":
            return {"status": 200, "body": "{}",
                    "content_type": "application/json"}
        raise TimeoutError("slow")
    res = parserdiff.scan("http://t", {"a": 1}, flaky)
    assert any(f.get("verdict") == "UNKNOWN" for f in res["findings"])


def test_graphqlx_introspection_disabled():
    def post(url, query):
        return {"status": 200, "body": '{"errors":[{"message":"off"}]}'}
    res = graphqlx.introspection("http://t/graphql", post)
    assert res["verdict"] == "PASS"
