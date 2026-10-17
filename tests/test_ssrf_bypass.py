from urllib.parse import urlparse

from engine import ssrf_bypass
from engine.roe_guard import ROEGuard


def _guard(in_scope, out_of_scope):
    return ROEGuard(
        roe={
            "enabled": True,
            "scope": {
                "in_scope": in_scope,
                "out_of_scope": out_of_scope,
                "allowed_methods": ["GET"],
                "forbidden_paths": [],
            },
        },
        engine_cfg={"roe": {"enforce_scope": True}},
    )


def test_ip_representations_canonical():
    reps = ssrf_bypass.ip_representations("127.0.0.1")
    assert "127.0.0.1" in reps
    assert "2130706433" in reps
    assert "0x7f000001" in reps
    assert "0177.0.0.1" in reps
    assert "127.1" in reps
    assert "127.0.1" in reps
    assert "0.0.0.0" in reps
    assert "[::1]" in reps
    assert any("::ffff:127.0.0.1" in r for r in reps)


def test_ip_representations_non_ip():
    assert ssrf_bypass.ip_representations("example.com") == ["example.com"]
    assert ssrf_bypass.ip_representations("") == []


def test_parser_confusion_userinfo():
    variants = ssrf_bypass.parser_confusion("http://127.0.0.1:8080/x")
    assert any("@127.0.0.1" in v for v in variants)
    assert any("127.0.0.1@" in v for v in variants)
    assert any("\\@" in v for v in variants)


def test_parser_confusion_backslash_and_no_slash():
    variants = ssrf_bypass.parser_confusion("https://127.0.0.1:8443/p")
    assert any(v.startswith("https:127.0.0.1") for v in variants)
    assert any(v.startswith("https:/127.0.0.1") for v in variants)


def test_scheme_juggling_coverage():
    joined = " ".join(ssrf_bypass.scheme_juggling("http://127.0.0.1:8080/"))
    for scheme in ("gopher://", "dict://", "file://", "ftp://",
                   "jar://", "netdoc://", "tftp://"):
        assert scheme in joined, "missing %s" % scheme


def test_dns_wildcards():
    hosts = ssrf_bypass.dns_wildcards("127.0.0.1")
    assert any("nip.io" in h for h in hosts)
    assert any("sslip.io" in h for h in hosts)
    assert "localtest.me" in hosts


def test_bypass_variants_of_url_contains_ip_repr():
    variants = ssrf_bypass.bypass_variants_of_url("http://127.0.0.1:8080/tok")
    assert "http://127.0.0.1:8080/tok" in variants
    assert "http://2130706433:8080/tok" in variants


def test_roe_allows_url_none_guard():
    assert ssrf_bypass.roe_allows_url(None, "http://example.com") is True


def test_roe_allows_url_blocks_out_of_scope():
    guard = _guard(["127.0.0.1", "169.254.169.254"],
                   ["169.254.169.254"])
    assert ssrf_bypass.roe_allows_url(
        guard, "http://169.254.169.254/latest/meta-data/") is False
    assert ssrf_bypass.roe_allows_url(
        guard, "http://127.0.0.1:8080/") is True


def test_metadata_urls_allowed_filters():
    guard = _guard(
        ["127.0.0.1", "169.254.169.254", "metadata.google.internal"],
        ["169.254.169.254", "metadata.google.internal"])
    allowed = ssrf_bypass.metadata_urls_allowed(guard)
    hosts = {urlparse(u).hostname for _l, u in allowed}
    assert "169.254.169.254" not in hosts
    assert "metadata.google.internal" not in hosts


def test_metadata_urls_allowed_empty_when_all_forbidden():
    guard = _guard(
        ["127.0.0.1", "169.254.169.254", "metadata.google.internal",
         "100.100.100.200"],
        ["169.254.169.254", "metadata.google.internal", "100.100.100.200"])
    assert ssrf_bypass.metadata_urls_allowed(guard) == []


def test_internal_port_bypasses_cover_expected_ports():
    bypasses = ssrf_bypass.internal_port_bypasses()
    assert len(bypasses) > 10
    labels = [l for l, _u in bypasses]
    for port in (8080, 6379, 9200):
        assert any("port_%d_" % port in l for l in labels)
