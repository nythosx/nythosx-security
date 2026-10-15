import json

from engine.brains.payload_author import PayloadAuthor


def test_offline_returns_fallback_numeric():
    pa = PayloadAuthor(client=None)
    variants = pa.tamper_variants("/api/checkout", {"price": 100}, kind="numeric")
    assert variants
    assert all("field" in v and "value" in v for v in variants)


def test_offline_returns_fallback_string():
    pa = PayloadAuthor(client=None)
    variants = pa.tamper_variants("/api/x", {"name": "x"}, kind="string")
    assert variants


def test_offline_returns_fallback_mass_assign():
    pa = PayloadAuthor(client=None)
    variants = pa.tamper_variants("/api/users", {"name": "x"},
                                  kind="mass_assign")
    fields = {v["field"] for v in variants}
    assert "is_admin" in fields or "role" in fields


def test_client_returns_valid_json():
    def client(prompt):
        return json.dumps({"variants": [
            {"field": "price", "value": -1, "rationale": "negative"},
            {"field": "price", "value": 0.001, "rationale": "tiny"},
        ]})
    pa = PayloadAuthor(client=client)
    variants = pa.tamper_variants("/api/checkout", {"price": 100})
    assert len(variants) == 2
    assert variants[0]["field"] == "price"


def test_client_garbage_falls_back():
    def client(prompt):
        return "not json"
    pa = PayloadAuthor(client=client)
    variants = pa.tamper_variants("/api/x", {"x": 1})
    assert variants


def test_canary_in_response_rejected():
    pa = PayloadAuthor(client=lambda p: "anything")
    leaked = json.dumps({"variants": [{"field": pa._canary, "value": 1,
                                        "rationale": "x"}]})
    pa2 = PayloadAuthor(client=lambda p: leaked)
    variants = pa2.tamper_variants("/x", {})
    assert variants
    assert all(pa2._canary not in v["field"] for v in variants)


def test_max_variants_respected():
    def client(prompt):
        return json.dumps({"variants": [
            {"field": f"f{i}", "value": i, "rationale": "x"}
            for i in range(50)
        ]})
    pa = PayloadAuthor(client=client, max_variants=3)
    variants = pa.tamper_variants("/x", {})
    assert len(variants) == 3


def test_fenced_json_parsed():
    def client(prompt):
        return '```json\n{"variants": [{"field": "f", "value": 1, ' \
               '"rationale": "x"}]}\n```'
    pa = PayloadAuthor(client=client)
    variants = pa.tamper_variants("/x", {})
    assert len(variants) == 1
    assert variants[0]["field"] == "f"
