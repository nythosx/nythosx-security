from engine import api_discovery as ad


def _mk(status=200, json=False, off_host=False, final_url=None, scheme="https",
        netloc="site.test"):
    def _f(url):
        fu = final_url or url
        return {
            "requested": url,
            "final_url": fu,
            "final_scheme": scheme,
            "final_netloc": netloc,
            "status": status,
            "json": json,
            "is_html": not json,
            "off_host": off_host,
            "is_redirect": 300 <= status < 400,
            "server": "cloudflare",
            "powered_by": "",
            "size": 10,
        }
    return _f


def test_prefers_versioned_json_base(monkeypatch):
    def fake_probe(url, timeout, follow):
        if "/api/v1/health" in url and url.startswith("https://"):
            return _mk(status=200, json=True, scheme="https",
                       netloc="site.test", final_url=url)(url)
        if url.rstrip("/") == "https://site.test" or url == "https://site.test/":
            return _mk(status=200, json=False)(url)
        return _mk(status=404, json=False)(url)

    monkeypatch.setattr(ad, "_probe", fake_probe)
    monkeypatch.setattr(ad, "detect_api_base_from_runtime", lambda u, a=None: None)
    monkeypatch.setattr(ad, "soft_404_fingerprint", lambda *a, **k: None)
    r = ad.discover("https://site.test")
    assert r["candidate_api_base"] == "https://site.test/api/v1"
    assert r["source"].startswith("same-origin")


def test_rejects_redirect_only_port(monkeypatch):
    def fake_probe(url, timeout, follow):
        if ":8080" in url:
            return _mk(status=301, json=False)(url)
        return None

    monkeypatch.setattr(ad, "_probe", fake_probe)
    monkeypatch.setattr(ad, "detect_api_base_from_runtime", lambda u, a=None: None)
    monkeypatch.setattr(ad, "soft_404_fingerprint", lambda *a, **k: None)
    monkeypatch.setattr(ad, "discover_same_origin", lambda u, c: None)
    r = ad.discover("https://site.test")
    assert r["candidate_api_base"] is None
    assert r["port_scan"] == []


def test_https_preferred_over_http_same_path(monkeypatch):
    def fake_probe(url, timeout, follow):
        if "/api" in url and not url.endswith("/api/v1") and "/api/v1" not in url:
            scheme = "https" if url.startswith("https") else "http"
            return _mk(status=200, json=True, scheme=scheme,
                       netloc="site.test", final_url=url)(url)
        return _mk(status=404, json=False)(url)

    monkeypatch.setattr(ad, "_probe", fake_probe)
    monkeypatch.setattr(ad, "detect_api_base_from_runtime", lambda u, a=None: None)
    monkeypatch.setattr(ad, "soft_404_fingerprint", lambda *a, **k: None)
    r = ad.discover("http://site.test")
    assert r["candidate_api_base"].startswith("https://")


def test_offhost_redirect_not_chosen(monkeypatch):
    def fake_probe(url, timeout, follow):
        return _mk(status=200, json=True, off_host=True,
                   final_url="https://elsewhere.test/api")(url)

    monkeypatch.setattr(ad, "_probe", fake_probe)
    monkeypatch.setattr(ad, "detect_api_base_from_runtime", lambda u, a=None: None)
    monkeypatch.setattr(ad, "soft_404_fingerprint", lambda *a, **k: None)
    r = ad.discover("https://site.test")
    assert r["candidate_api_base"] is None
