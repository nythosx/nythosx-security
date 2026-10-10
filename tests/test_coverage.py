def test_report_shape():
    from engine import coverage
    r = coverage.build_coverage_report(
        target="http://t",
        findings=[{"pattern_id": "env-file-exposure", "verdict": "VULNERABLE"}],
        executed_caps=["env-file-exposure"],
        profile="standard",
    )
    for key in ("owasp", "attack_surfaces", "unrun_capabilities",
                "untested_categories", "executed_count", "total_count"):
        assert key in r


def test_untested_categories_detected():
    from engine import coverage
    r = coverage.build_coverage_report(executed_caps=[])
    assert "A09" in r["untested_categories"]


def test_executed_capability_marked_in_owasp():
    from engine import coverage
    r = coverage.build_coverage_report(executed_caps=["env-file-exposure"])
    a02 = r["owasp"]["A02"]
    assert "env-file-exposure" in a02["executed"]
    assert "env-file-exposure" not in a02["missing"]


def test_attack_surfaces_present():
    from engine import coverage
    r = coverage.build_coverage_report(executed_caps=[])
    assert "rest" in r["attack_surfaces"]
    assert "graphql" in r["attack_surfaces"]
    assert "llm" in r["attack_surfaces"]


def test_unrun_capabilities_deduped():
    from engine import coverage
    r = coverage.build_coverage_report(executed_caps=["env-file-exposure"])
    assert r["unrun_capabilities"] == sorted(set(r["unrun_capabilities"]))


def test_scanresult_input_accepted():
    from engine import coverage
    from engine.contract import ScanResult
    r1 = ScanResult(capability="env-file-exposure", target="http://t")
    r = coverage.build_coverage_report(findings=[r1])
    assert "env-file-exposure" in r["owasp"]["A02"]["executed"]
