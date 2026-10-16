from engine.schema import (
    is_broad_scope_wildcard,
    find_broad_scope_wildcards,
)


def test_star_is_broad():
    assert is_broad_scope_wildcard("*") is True


def test_star_dot_is_broad():
    assert is_broad_scope_wildcard("*.") is True


def test_star_dot_star_is_broad():
    assert is_broad_scope_wildcard("*.*") is True


def test_broad_tld_wildcard_is_broad():
    assert is_broad_scope_wildcard("*.com") is True
    assert is_broad_scope_wildcard("*.io") is True
    assert is_broad_scope_wildcard("*.gov") is True


def test_specific_host_not_broad():
    assert is_broad_scope_wildcard("nythosx.com") is False
    assert is_broad_scope_wildcard("*.nythosx.com") is False
    assert is_broad_scope_wildcard("scanme.nmap.org") is False
    assert is_broad_scope_wildcard("localhost") is False
    assert is_broad_scope_wildcard("127.0.0.1") is False


def test_cidr_zero_is_broad():
    assert is_broad_scope_wildcard("0.0.0.0/0") is True
    assert is_broad_scope_wildcard("10.0.0.0/0") is True


def test_find_broad_scope_returns_offenders():
    roe = {
        "scope": {
            "in_scope": [
                "nythosx.com",
                "*.",
                "*.com",
                "localhost",
            ]
        }
    }
    offenders = find_broad_scope_wildcards(roe)
    assert "*." in offenders
    assert "*.com" in offenders
    assert "nythosx.com" not in offenders
    assert "localhost" not in offenders


def test_empty_and_none_safe():
    assert is_broad_scope_wildcard("") is False
    assert is_broad_scope_wildcard(None) is False
