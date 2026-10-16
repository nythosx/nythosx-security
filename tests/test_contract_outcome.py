from engine.contract import Outcome, ScanResult, coerce_outcome


def test_outcome_enum_values():
    assert Outcome.NONE.value == "NONE"
    assert Outcome.ACCESS_GRANTED.value == "ACCESS_GRANTED"
    assert Outcome.DATA_LEAKED.value == "DATA_LEAKED"
    assert Outcome.CODE_EXECUTED.value == "CODE_EXECUTED"


def test_coerce_outcome():
    assert coerce_outcome(None) is Outcome.NONE
    assert coerce_outcome("access_granted") is Outcome.ACCESS_GRANTED
    assert coerce_outcome("GARBAGE") is Outcome.NONE
    assert coerce_outcome(Outcome.IDENTITY) is Outcome.IDENTITY


def test_scan_result_defaults():
    r = ScanResult(capability="x", target="y")
    assert r.outcome is Outcome.NONE
    assert r.artifact_ref == ""


def test_scan_result_to_dict_includes_outcome():
    r = ScanResult(
        capability="x",
        target="y",
        outcome=Outcome.DATA_LEAKED,
        artifact_ref="art-1",
    )
    d = r.to_dict()
    assert d["outcome"] == "DATA_LEAKED"
    assert d["artifact_ref"] == "art-1"


def test_scan_result_getitem_outcome():
    r = ScanResult(
        capability="x",
        target="y",
        outcome=Outcome.SESSION_MATERIAL,
    )
    assert r["outcome"] == "SESSION_MATERIAL"


def test_scan_result_contains_outcome():
    r = ScanResult(capability="x", target="y")
    assert "outcome" in r
    assert "artifact_ref" in r
