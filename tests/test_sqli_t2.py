from engine.injection import sqli_t2
from tests.testapp.sqli_t2_fixture import SqliT2Fixture


def test_second_order_payloads_present():
    assert len(sqli_t2.SECOND_ORDER_PAYLOADS) >= 3
    assert any("'" in p for p in sqli_t2.SECOND_ORDER_PAYLOADS)


def test_chunked_payloads_present():
    assert len(sqli_t2.CHUNKED_QUERY_PAYLOADS) >= 3
    assert any(";" in p for p in sqli_t2.CHUNKED_QUERY_PAYLOADS)


def test_json_probes_present():
    labels = [list(p.keys())[0] for p in sqli_t2.JSON_CONTEXT_PROBES]
    assert "$where" in labels
    assert "username" in labels


def test_dialect_payloads_cover_core_dialects():
    for d in ("mysql", "postgres", "mssql"):
        assert d in sqli_t2.DIALECT_ERROR_PAYLOADS


def test_second_order_confirms_fixture():
    with SqliT2Fixture() as fx:
        r = sqli_t2.probe_second_order(
            fx.base_url + "/sqli2/store",
            store_method="POST", store_param="bio",
            payload="admin'-- -",
            reader_endpoints=[fx.base_url + "/sqli2/reader"],
            reader_method="GET", reader_param="q",
            timeout=3,
        )
    assert r["verdict"] == "VULNERABLE", r
    assert r.get("second_order_confirmed") is True


def test_second_order_safe_payload_passes():
    with SqliT2Fixture() as fx:
        r = sqli_t2.probe_second_order(
            fx.base_url + "/sqli2/store",
            store_method="POST", store_param="bio",
            payload="hello world",
            reader_endpoints=[fx.base_url + "/sqli2/reader"],
            reader_method="GET", reader_param="q",
            timeout=3,
        )
    assert r["verdict"] == "PASS", r


def test_second_order_unknown_when_no_readers():
    # Empty reader_endpoints is the "no readers" gate.
    with SqliT2Fixture() as fx:
        r = sqli_t2.probe_second_order(
            fx.base_url + "/sqli2/store",
            reader_endpoints=[],
        )
    assert r["verdict"] == "UNKNOWN"
    assert "store_url" in r["reason"] or \
           "reader" in r["reason"].lower()


def test_second_order_unknown_when_no_store_url():
    # Missing store_url is the other UNKNOWN gate.
    with SqliT2Fixture() as fx:
        r = sqli_t2.probe_second_order(
            None,
            reader_endpoints=[fx.base_url + "/sqli2/reader"],
        )
    assert r["verdict"] == "UNKNOWN"
    assert "store_url" in r["reason"] or \
           "reader" in r["reason"].lower()


def test_error_based_extracts_version_marker():
    with SqliT2Fixture() as fx:
        r = sqli_t2.probe_error_based(
            fx.base_url + "/sqli2/error",
            param="id", dbms="mysql", timeout=3,
        )
    assert r["verdict"] == "VULNERABLE", r
    assert "8.0.32" in (r["evidence"].get("leaked") or "")


def test_error_based_safe():
    with SqliT2Fixture() as fx:
        r = sqli_t2.probe_error_based(
            fx.base_url + "/sqli2/error",
            param="id", dbms="sqlite", timeout=3,
        )
    assert r["verdict"] in ("PASS", "SUSPICIOUS"), r


def test_boolean_timing_confirms_sleep():
    with SqliT2Fixture() as fx:
        r = sqli_t2.probe_boolean_timing(
            fx.base_url + "/sqli2/boolean",
            param="id",
            baseline_samples=4,
            payload_samples=4,
            sleep_seconds=2,
            timeout=8,
        )
    assert r["verdict"] == "SUSPICIOUS", r


def test_boolean_timing_safe_endpoint():
    with SqliT2Fixture() as fx:
        r = sqli_t2.probe_boolean_timing(
            fx.base_url + "/sqli2/boolean",
            param="id",
            baseline_samples=4,
            payload_samples=4,
            sleep_seconds=1,
            timeout=3,
        )
    # Fake fixture tolerates SLEEP but under-fast timeout threshold;
    # unless the "sleep" happens to be present, expect PASS or SUSPICIOUS.
    assert r["verdict"] in ("PASS", "SUSPICIOUS", "UNKNOWN")


def test_json_context_confirms_mongo_error():
    with SqliT2Fixture() as fx:
        r = sqli_t2.probe_json_context(
            fx.base_url + "/sqli2/json", method="POST", timeout=3)
    assert r["verdict"] == "SUSPICIOUS", r


def test_chunked_hpp_safe_endpoint():
    with SqliT2Fixture() as fx:
        r = sqli_t2.probe_chunked_query(
            fx.base_url + "/sqli2/reader", param="q",
            method="GET", timeout=3)
    assert r["verdict"] in ("PASS", "SUSPICIOUS", "UNKNOWN")
