from engine.parserdiff import boundary_diff
from tests.testapp.parserdiff_fixture import BoundaryFixture


def test_probes_are_sent():
    with BoundaryFixture() as fx:
        result = boundary_diff.probe_ambiguity(
            fx.base_url + "/boundary/strict", timeout=2)
        assert result["probes"]
        # clean probe present
        ids = [p["id"] for p in result["probes"]]
        assert "dup_cl_disagree" in ids
        assert "cl_te_conflict" in ids
        assert "clean" in ids


def test_strict_matrix():
    with BoundaryFixture() as fx:
        result = boundary_diff.probe_ambiguity(
            fx.base_url + "/boundary/strict", timeout=2)
    matrix = boundary_diff.analyze_winner_matrix(result["probes"])
    assert matrix["winning_side"]["dup_cl_disagree"] == "strict"
    assert matrix["winning_side"]["cl_te_conflict"] == "strict"
    assert matrix["exploitable_ambiguities"] == []


def test_lenient_cl_matrix():
    with BoundaryFixture() as fx:
        result = boundary_diff.probe_ambiguity(
            fx.base_url + "/boundary/lenient_cl", timeout=2)
    matrix = boundary_diff.analyze_winner_matrix(result["probes"])
    assert matrix["winning_side"]["cl_te_conflict"] == "cl"
    assert matrix["winning_side"]["dup_cl_disagree"] == "cl_last"
    assert "cl_te_conflict" in matrix["exploitable_ambiguities"]
    assert "dup_cl_disagree" in matrix["exploitable_ambiguities"]


def test_lenient_te_matrix():
    with BoundaryFixture() as fx:
        result = boundary_diff.probe_ambiguity(
            fx.base_url + "/boundary/lenient_te", timeout=2)
    matrix = boundary_diff.analyze_winner_matrix(result["probes"])
    assert matrix["winning_side"]["cl_te_conflict"] == "te"
    assert "cl_te_conflict" in matrix["exploitable_ambiguities"]


def test_extract_desync_surface_strict():
    with BoundaryFixture() as fx:
        result = boundary_diff.extract_desync_surface(
            fx.base_url + "/boundary/strict", timeout=2)
    assert result["verdict"] == "PASS"
    assert result["desync_surface"]["exploitable_ambiguities"] == []


def test_extract_desync_surface_lenient_cl():
    with BoundaryFixture() as fx:
        result = boundary_diff.extract_desync_surface(
            fx.base_url + "/boundary/lenient_cl", timeout=2)
    assert result["verdict"] == "VULNERABLE"
    assert result["desync_surface"]["exploitable_ambiguities"]


def test_frontend_class_detection_unknown():
    with BoundaryFixture() as fx:
        cls = boundary_diff.detect_frontend_class(
            fx.base_url + "/boundary/strict", timeout=2)
    assert cls == "unknown"


def test_roe_blocked():
    from engine.roe_guard import ROEGuard
    guard = ROEGuard(
        roe={"enabled": True, "scope": {
            "in_scope": ["example.invalid"],
            "out_of_scope": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_paths": [],
        }},
        engine_cfg={"roe": {"enforce_scope": True,
                             "enforce_methods": True}},
    )
    with BoundaryFixture() as fx:
        result = boundary_diff.probe_ambiguity(
            fx.base_url + "/boundary/strict", timeout=2, roe_guard=guard)
    assert result.get("blocked") is True
