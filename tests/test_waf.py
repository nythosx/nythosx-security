from engine.waf import fingerprint, encoder


def _resp(status=403, headers=None, body=""):
    return {"status": status, "headers": headers or {}, "body": body}


def test_identify_none():
    assert fingerprint.identify(None)["waf"] is None


def test_identify_cloudflare_by_headers():
    r = _resp(headers={"cf-ray": "abc123", "Server": "cloudflare"})
    fp = fingerprint.identify(r)
    assert fp["waf"] == "cloudflare"
    assert fp["confidence"] >= 0.3


def test_identify_akamai():
    r = _resp(headers={"X-Akamai-Request-ID": "xyz"})
    assert fingerprint.identify(r)["waf"] == "akamai"


def test_identify_aws_waf_by_body():
    r = _resp(body="<html>Request blocked by AWS WAF</html>")
    assert fingerprint.identify(r)["waf"] == "aws_waf"


def test_identify_imperva():
    r = _resp(headers={"X-Iinfo": "1-2-3"})
    assert fingerprint.identify(r)["waf"] == "imperva_incapsula"


def test_identify_sucuri():
    r = _resp(body="Sucuri Website Firewall - Access Denied")
    assert fingerprint.identify(r)["waf"] == "sucuri"


def test_identify_unknown_waf_returns_none():
    r = _resp(headers={"Server": "nginx/1.18"}, body="hello")
    assert fingerprint.identify(r)["waf"] is None


def test_is_waf_block_403_with_sig():
    r = _resp(status=403, headers={"cf-ray": "abc"})
    assert fingerprint.is_waf_block(403, r) is True


def test_is_waf_block_200_returns_false():
    r = _resp(status=200, headers={"cf-ray": "abc"})
    assert fingerprint.is_waf_block(200, r) is False


def test_encode_basic():
    out = encoder.encode("' OR 1=1--")
    names = [n for n, _ in out]
    assert "url_single" in names
    assert "url_double" in names
    assert "case_alternate" in names
    assert "unicode_escape" in names


def test_encode_no_dupes():
    out = encoder.encode("abc")
    vals = [v for _, v in out]
    assert len(vals) == len(set(vals))


def test_encode_waf_specific_cloudflare():
    out = encoder.encode("' OR 1=1--", waf="cloudflare")
    names = [n for n, _ in out]
    assert any(n.startswith("cf_") for n in names)


def test_encode_empty_returns_empty():
    assert encoder.encode("") == []


def test_encode_max_mutations():
    out = encoder.encode("' UNION SELECT 1,2,3--", waf="cloudflare",
                         max_mutations=5)
    assert len(out) <= 5


def test_encode_all_multiple_wafs():
    out = encoder.encode_all("' OR 1=1", wafs=["cloudflare", "akamai"],
                             max_per_waf=3)
    names = [n for n, _ in out]
    assert any(n.startswith("cloudflare:") for n in names)
    assert any(n.startswith("akamai:") for n in names)
