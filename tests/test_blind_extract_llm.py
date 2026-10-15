import re

from engine import blind_extract, llm_service


SECRET = "a@b.co"


def _fake_send_factory(counter):
    def fake(url, param, payload, method, headers, timeout, verify, roe_guard):
        counter[0] += 1
        m = re.search(r",(\d+),1\)\)>(\d+)", payload)
        base = 10.0
        if not m:
            return {"status": 200, "body": "", "elapsed_ms": base}
        pos = int(m.group(1))
        char = int(m.group(2))
        hit = pos - 1 < len(SECRET) and ord(SECRET[pos - 1]) > char
        return {"status": 200, "body": "",
                "elapsed_ms": base + (5000.0 if hit else 0.0)}
    return fake


def test_extract_no_prior_binary_search(monkeypatch):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    c = [0]
    monkeypatch.setattr(blind_extract, "_send", _fake_send_factory(c))
    r = blind_extract.extract_string("http://t/", "q", "users", "password",
                                     dbms="mysql", max_length=len(SECRET) + 1)
    assert r["extracted"] == SECRET
    no_prior_requests = r["requests"]
    assert no_prior_requests > 0


def test_extract_correct_prior_uses_fewer_requests(monkeypatch):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    c1 = [0]
    monkeypatch.setattr(blind_extract, "_send", _fake_send_factory(c1))
    base = blind_extract.extract_string("http://t/", "q", "users", "password",
                                        dbms="mysql", max_length=len(SECRET) + 1)
    c2 = [0]
    monkeypatch.setattr(blind_extract, "_send", _fake_send_factory(c2))
    guided = blind_extract.extract_string(
        "http://t/", "q", "users", "password", dbms="mysql",
        max_length=len(SECRET) + 1, prior=SECRET)
    assert guided["extracted"] == SECRET
    assert guided["requests"] < base["requests"]


def test_extract_wrong_prior_falls_back(monkeypatch):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    c = [0]
    monkeypatch.setattr(blind_extract, "_send", _fake_send_factory(c))
    r = blind_extract.extract_string(
        "http://t/", "q", "users", "password", dbms="mysql",
        max_length=len(SECRET) + 1, prior="ZZZZZZ")
    assert r["extracted"] == SECRET


def test_llm_prior_none_without_ai(monkeypatch):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    assert blind_extract._llm_extract_prior("users", "password", "mysql") == ""
