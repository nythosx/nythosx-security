import pytest

from engine.roe_guard import ROEGuard, ROEViolation


ROE = {
    "enabled": True,
    "scope": {
        "in_scope": ["site.test"],
        "out_of_scope": [],
        "allowed_methods": ["GET"],
        "forbidden_paths": ["/admin"],
    },
}


def _encode_path_n(path, n):
    assert path.startswith("/"), path
    body = path[1:]
    for _ in range(n):
        body = body.replace("%", "%25").replace("/", "%2f")
    return "/" + body


def _assert_forbidden(g, url):
    with pytest.raises(ROEViolation) as exc:
        g.check_url(url, "GET")
    msg = str(exc.value)
    assert "FORBIDDEN PATH" in msg, (
        f"expected FORBIDDEN PATH, got: {msg}")


def _assert_in_scope(g, url):
    assert g.check_url(url, "GET")


def test_single_encode_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test" + _encode_path_n("/admin", 1))


def test_double_encode_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test" + _encode_path_n("/admin", 2))


def test_triple_encode_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test" + _encode_path_n("/admin", 3))


def test_quad_encode_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test" + _encode_path_n("/admin", 4))


def test_quint_encode_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test" + _encode_path_n("/admin", 5))


def test_raw_path_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test/admin")


def test_safe_path_allowed():
    g = ROEGuard(ROE)
    _assert_in_scope(g, "http://site.test/api/users")


def test_single_encoded_safe_path_allowed():
    g = ROEGuard(ROE)
    _assert_in_scope(g, "http://site.test" + _encode_path_n("/api/users", 1))


def test_double_encoded_safe_path_allowed():
    g = ROEGuard(ROE)
    _assert_in_scope(g, "http://site.test" + _encode_path_n("/api/users", 2))


def test_triple_encoded_safe_path_allowed():
    g = ROEGuard(ROE)
    _assert_in_scope(g, "http://site.test" + _encode_path_n("/api/users", 3))


def test_dot_segment_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test/foo/../admin")


def test_double_encoded_dot_segment_blocked():
    g = ROEGuard(ROE)
    g_enc = _encode_path_n("/foo/../admin", 2)
    _assert_forbidden(g, "http://site.test" + g_enc)


def test_double_slash_collapse_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test//admin")


def test_encoded_slash_then_admin_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test/%2fadmin")


def test_encoded_dot_then_admin_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test/%2e/admin")


def test_mixed_case_forbidden_path_blocked():
    g = ROEGuard(ROE)
    _assert_forbidden(g, "http://site.test/Admin")


def test_deeply_encoded_beyond_cap_still_blocked():
    # Beyond the loop cap (5), the normalized path won't decode further, but
    # the raw/decoded variants are still compared against forbidden patterns
    # so the check remains conservative.
    g = ROEGuard(ROE)
    encoded = _encode_path_n("/admin", 6)
    url = "http://site.test" + encoded
    with pytest.raises(ROEViolation):
        g.check_url(url, "GET")
