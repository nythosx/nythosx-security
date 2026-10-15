from engine.oracle import evaluate


def _step(headers, status=200):
    return {
        "step_name": "probe", "status": status, "body": "",
        "headers": headers, "time_ms": 10.0, "body_hash": "h",
        "url": "http://t/",
    }


def _ctx(headers):
    return {"steps": [_step(headers)], "inputs": {},
            "target": "http://t", "negative_baseline": None}


def test_substring_prefix_not_matched():
    ctx = _ctx({"access-control-allow-origin": "https://notattacker.example.com"})
    o = {"type": "cors_misconfig",
         "test_origin": "https://attacker.example.com"}
    r = evaluate(o, ctx)
    assert r["verdict"] == "PASS"


def test_substring_suffix_not_matched():
    ctx = _ctx({"access-control-allow-origin": "https://attacker.example.com.evil.io"})
    o = {"type": "cors_misconfig",
         "test_origin": "https://attacker.example.com"}
    r = evaluate(o, ctx)
    assert r["verdict"] == "PASS"


def test_exact_origin_matched():
    ctx = _ctx({"access-control-allow-origin": "https://attacker.example.com"})
    o = {"type": "cors_misconfig",
         "test_origin": "https://attacker.example.com"}
    r = evaluate(o, ctx)
    assert r["verdict"] == "VULNERABLE"


def test_subdomain_reflection_matched():
    ctx = _ctx({"access-control-allow-origin":
                "https://sub.attacker.example.com"})
    o = {"type": "cors_misconfig",
         "test_origin": "https://attacker.example.com"}
    r = evaluate(o, ctx)
    assert r["verdict"] == "VULNERABLE"


def test_wildcard_still_pass():
    ctx = _ctx({"access-control-allow-origin": "*"})
    o = {"type": "cors_misconfig",
         "test_origin": "https://attacker.example.com"}
    r = evaluate(o, ctx)
    assert r["verdict"] == "PASS"


def test_wildcard_with_creds_suspicious():
    ctx = _ctx({"access-control-allow-origin": "*",
                "access-control-allow-credentials": "true"})
    o = {"type": "cors_misconfig",
         "test_origin": "https://attacker.example.com"}
    r = evaluate(o, ctx)
    assert r["verdict"] == "SUSPICIOUS"
