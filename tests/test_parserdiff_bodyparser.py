from engine.parserdiff import bodyparser_diff
from tests.testapp.parserdiff_fixture import HttpFixture


def test_serializations_count():
    serializations = bodyparser_diff.make_serializations()
    assert len(serializations) == 8
    labels = [s[0] for s in serializations]
    assert "json_canonical" in labels
    assert "json_duplicate_key" in labels
    assert "json5_unquoted" in labels
    assert "xml_against_json" in labels
    assert "form_bracket" in labels
    assert "json_bom" in labels


def test_serialization_content_types():
    serializations = bodyparser_diff.make_serializations()
    for label, ct, body in serializations:
        assert ct, "missing CT for %s" % label
        assert body, "missing body for %s" % label


def test_json_only_fixture():
    with HttpFixture() as fx:
        result = bodyparser_diff.detect_bodyparser_divergence(
            fx.base_url + "/bodyparser/json_only", timeout=3)
    assert result["verdict"] == "VULNERABLE"
    assert result["divergence"]["divergence"]
    assert "json_canonical" in result["divergence"]["accepted_serializations"]
    assert "form_bracket" in result["divergence"]["rejected_serializations"]


def test_both_fixture():
    with HttpFixture() as fx:
        result = bodyparser_diff.detect_bodyparser_divergence(
            fx.base_url + "/bodyparser/both", timeout=3)
    acc = result["divergence"]["accepted_serializations"]
    assert "json_canonical" in acc
    assert "form_bracket" in acc
    assert "xml_against_json" not in acc


def test_analyze_divergence_empty():
    result = bodyparser_diff.analyze_divergence([])
    assert result["divergence"] is False
    assert result["accepted_serializations"] == []
    assert result["rejected_serializations"] == []
