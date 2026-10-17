from engine.parserdiff import charset_diff
from tests.testapp.parserdiff_fixture import HttpFixture


def test_charset_variants_count():
    variants = charset_diff.make_charset_variants("test")
    labels = [v[0] for v in variants]
    assert "utf8_plain" in labels
    assert "utf16le_declared_utf8" in labels
    assert "nfc" in " ".join(labels)
    assert "nfkc" in " ".join(labels)


def test_homoglyphs_detects_cyrillic_a():
    variants = charset_diff.make_homoglyphs("admin")
    assert any(orig == "a" for orig, _r, _m in variants)
    cyr = [m for orig, r, m in variants if orig == "a" and r == "\u0430"]
    assert cyr, "cyrillic a homoglyph not generated"
    assert cyr[0] != "admin"


def test_normalize_nfkc():
    # NFKC collapses compatibility chars (fullwidth -> ASCII)
    # but does NOT transliterate between scripts. Cyrillic a
    # stays Cyrillic a. That distinction is exactly why
    # homoglyph bypasses work: the parser sees a distinct codepoint.
    assert charset_diff.normalize("\uff41dmin", "NFKC") == "admin"
    assert charset_diff.normalize("\u0430dmin", "NFKC") == "\u0430dmin"


def test_charset_strict_fixture():
    with HttpFixture() as fx:
        result = charset_diff.detect_charset_divergence(
            fx.base_url + "/charset/auth_strict",
            param="username", timeout=3)
    assert result["verdict"] == "VULNERABLE"
    assert result["divergence"]["charset_sensitive"]


def test_charset_lenient_fixture():
    with HttpFixture() as fx:
        result = charset_diff.detect_charset_divergence(
            fx.base_url + "/charset/auth_lenient",
            param="username", timeout=3)
    assert result["verdict"] == "VULNERABLE"


def test_path_traversals_present():
    assert "..%c0%af" in charset_diff.PATH_TRAVERSALS
    assert "..%2f" in charset_diff.PATH_TRAVERSALS
    assert len(charset_diff.PATH_TRAVERSALS) >= 8


def test_unicode_line_separator_variants():
    variants = charset_diff.unicode_line_separator_variants("x")
    assert len(variants) == 2
    labels = [v["label"] for v in variants]
    assert "u2028_embedded" in labels
    assert "u2029_embedded" in labels

def test_homoglyph_bypass_strict_fixture():
    # strict: \u0430dmin is NOT admin (no folding)
    with HttpFixture() as fx:
        result = charset_diff.homoglyph_bypass_probe(
            fx.base_url + "/charset/auth_strict",
            param="username", baseline_value="admin",
            timeout=3)
    accepted = [a for a in result["attempts"]
                if a.get("accepted")]
    assert accepted == [], (
        "strict fixture falsely accepted a homoglyph: %r"
        % accepted)


def test_homoglyph_bypass_lenient_fixture():
    # lenient folds Cyrillic -> Latin: \u0430dmin == admin
    with HttpFixture() as fx:
        result = charset_diff.homoglyph_bypass_probe(
            fx.base_url + "/charset/auth_lenient",
            param="username", baseline_value="admin",
            timeout=3)
    accepted = [a for a in result["attempts"]
                if a.get("accepted")]
    assert accepted, (
        "lenient fixture did not accept any homoglyph; "
        "got %r" % result["attempts"])
