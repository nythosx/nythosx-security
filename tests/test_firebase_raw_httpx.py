def test_firebase_probe_does_not_use_engine_http():
    import engine.firebase_probe as fp
    assert not hasattr(fp, "_http"), (
        "firebase_probe must not use engine.http.Client \u2014 its URLs are "
        "on firebaseio.com and firebaseapp.com, which are not in the ROE "
        "scope. Use raw httpx.Client."
    )


def test_firebase_probe_uses_external_http():
    """firebase_probe must route through engine.external_http, not raw httpx.

    Firebase API endpoints are a non-target external service. The shared
    external rate limiter and per-host circuit breaker live in
    engine.external_http; calling httpx.Client directly would bypass both.
    """
    import inspect
    import engine.firebase_probe as fp
    src = inspect.getsource(fp)
    assert "external_http.Client(" in src, (
        "firebase_probe must call external_http.Client")


def test_firebase_candidate_hosts_are_third_party():
    from engine.firebase_probe import _firebase_candidates
    urls = _firebase_candidates("https://nythosx.com")
    assert urls
    for u in urls:
        assert "firebaseio.com" in u or "firebaseapp.com" in u
