from engine import registry


def test_unknown_capability_no_approval():
    assert registry.requires_approval("zzz_unknown_zzz") is False


def test_non_destructive_capability_no_approval():
    registry.reset()
    assert registry.requires_approval("sec_route") is False
    assert registry.requires_approval("sec_list_patterns") is False


def test_destructive_default_requires_approval():
    registry.reset()
    assert registry.requires_approval("race_scan") is True
    assert registry.requires_approval("upload_scan") is True
    assert registry.requires_approval("weak_credential_enum") is True


def test_scoped_destructive_matches_in_scope():
    registry.reset()
    assert registry.requires_approval(
        "race_scan", "https://x.test/api/v1/cart"
    ) is True
    assert registry.requires_approval(
        "race_scan", "https://x.test/api/v2/checkout"
    ) is True


def test_scoped_destructive_out_of_scope():
    registry.reset()
    assert registry.requires_approval(
        "race_scan", "https://x.test/public/status"
    ) is False
    assert registry.requires_approval(
        "race_scan", "https://x.test/admin"
    ) is False


def test_scoped_destructive_empty_url_defaults_to_approval():
    registry.reset()
    assert registry.requires_approval("race_scan", "") is True


def test_always_approve_capabilities():
    registry.reset()
    assert registry.requires_approval(
        "upload_scan", "https://x.test/api/v1/upload"
    ) is True
    assert registry.requires_approval(
        "upload_scan", "https://x.test/anything"
    ) is True
    assert registry.requires_approval(
        "upload_scan", ""
    ) is True


def test_url_pattern_matching_paths():
    assert registry._url_matches_pattern(
        "https://x.test/api/v1/cart", "/api/v1/"
    ) is True
    assert registry._url_matches_pattern(
        "https://x.test/other", "/api/v1/"
    ) is False
    assert registry._url_matches_pattern(
        "https://x.test/api/v1/cart", "/api/**"
    ) is True


def test_url_pattern_matching_hosts():
    assert registry._url_matches_pattern(
        "https://api.example.com/x", "*.example.com"
    ) is True
    assert registry._url_matches_pattern(
        "https://api.example.com/x", "example.com"
    ) is False
    assert registry._url_matches_pattern(
        "https://api.example.com/x", "api.example.com"
    ) is True


def test_url_pattern_safe_on_empty():
    assert registry._url_matches_pattern("", "/api/") is False
    assert registry._url_matches_pattern("https://x.test", "") is False
