import pytest


def test_every_pattern_has_writeup():
    from engine import loader, writeup_library
    patterns = loader.list_patterns()
    assert patterns
    for p in patterns:
        entry = writeup_library.resolve(p["id"])
        assert entry is not None, f"no writeup for pattern {p['id']}"


def test_render_returns_required_parts():
    from engine import writeup_library
    entry = writeup_library.resolve("env-file-exposure")
    assert entry is not None
    rendered = writeup_library.render(entry, {"url_path": "/.env"})
    for key in ("attack", "gap", "impact", "fix"):
        assert key in rendered
        assert isinstance(rendered[key], str)
        assert rendered[key]


def test_unresolved_pattern_returns_none():
    from engine import writeup_library
    assert writeup_library.resolve("does-not-exist-xyz") is None


def test_vars_interpolated_from_evidence():
    from engine import writeup_library
    entry = writeup_library.resolve("security-headers-missing")
    assert entry is not None
    rendered = writeup_library.render(entry, {"missing_headers": ["HSTS", "CSP"]})
    assert "HSTS" in rendered["gap"]
    assert "CSP" in rendered["gap"]


def test_missing_evidence_uses_default():
    from engine import writeup_library
    entry = writeup_library.resolve("security-headers-missing")
    rendered = writeup_library.render(entry, {})
    assert "{header}" not in rendered["gap"]


def test_families_loaded():
    from engine import writeup_library
    fams = writeup_library.families()
    assert isinstance(fams, dict)
    assert len(fams) >= 15


def test_coverage_missing_empty_for_current_patterns():
    from engine import loader, writeup_library
    ids = [p["id"] for p in loader.list_patterns()]
    missing = writeup_library.coverage_missing(ids)
    assert missing == []
