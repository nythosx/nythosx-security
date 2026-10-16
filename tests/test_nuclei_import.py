import json
import textwrap


class _Resp:
    def __init__(self, status_code=200, body="", headers=None):
        self.status_code = status_code
        self.text = body
        self.headers = headers or {"Content-Type": "text/html"}
        self.cookies = {}
        self.url = "http://x/"
        self.elapsed = None


class _FakeClient:
    def __init__(self, response):
        self._r = response
        self.last = None

    def request(self, method, url, **kw):
        self.last = {"method": method, "url": url, **kw}
        return self._r

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _install_client(monkeypatch, response):
    from engine import http as _http
    holder = {}

    def _ctor(*a, **kw):
        c = _FakeClient(response)
        holder["c"] = c
        return c

    monkeypatch.setattr(_http, "Client", _ctor)
    return holder


class _Orch:
    def __init__(self, target="https://t.test"):
        self.target = target


def test_import_module_has_registered_tool():
    from engine import nuclei_import
    from engine.chain_engine import _EXTRA_HANDLERS
    nuclei_import.ensure_registered()
    assert "nuclei_http" in _EXTRA_HANDLERS


def test_template_to_chain_basic():
    from engine import nuclei_import
    tpl = {
        "id": "test-x",
        "info": {"name": "Test", "severity": "high"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"],
                  "matchers": [{"type": "status", "status": [200]}]}],
    }
    chain = nuclei_import.template_to_chain(tpl)
    assert chain["id"] == "nuclei-test-x"
    assert chain["priority"] == 700
    assert len(chain["steps"]) == 1
    assert chain["steps"][0]["tool"] == "nuclei_http"
    assert chain["steps"][0]["on_fail"] == "next"


def test_template_validates_against_schema():
    from engine import nuclei_import
    from engine import schema
    tpl = {
        "id": "ok-1",
        "info": {"name": "Ok", "severity": "medium"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/a"]}],
    }
    chain = nuclei_import.template_to_chain(tpl)
    schema.validate_chain(chain, where="nuclei-ok-1")


def test_template_with_requests_key():
    from engine import nuclei_import
    tpl = {"id": "r1", "info": {"name": "R"}, "requests": [
        {"method": "GET", "path": ["/a"]}]}
    chain = nuclei_import.template_to_chain(tpl)
    assert len(chain["steps"]) == 1


def test_matcher_status_positive(monkeypatch):
    from engine import nuclei_import
    _install_client(monkeypatch, _Resp(200, "hello"))
    handler = None
    from engine import nuclei_import as _ni
    handler = _ni._tool_nuclei_http
    out = handler(_Orch(), {"request": {
        "method": "GET", "path": ["/x"],
        "matchers": [{"type": "status", "status": [200]}]},
        "template_id": "t"})
    assert out["verdict"] == "VULNERABLE"
    assert out["evidence"]["status"] == 200


def test_matcher_status_negative(monkeypatch):
    from engine import nuclei_import
    _install_client(monkeypatch, _Resp(404, "nope"))
    out = nuclei_import._tool_nuclei_http(_Orch(), {"request": {
        "method": "GET", "path": ["/x"],
        "matchers": [{"type": "status", "status": [200]}]},
        "template_id": "t"})
    assert out["verdict"] == "PASS"


def test_matcher_word_or(monkeypatch):
    from engine import nuclei_import
    _install_client(monkeypatch, _Resp(200, "hello world"))
    out = nuclei_import._tool_nuclei_http(_Orch(), {"request": {
        "method": "GET", "path": ["/x"],
        "matchers": [{"type": "word", "words": ["nope", "world"]}]},
        "template_id": "t"})
    assert out["verdict"] == "VULNERABLE"


def test_matcher_word_and_fails(monkeypatch):
    from engine import nuclei_import
    _install_client(monkeypatch, _Resp(200, "hello world"))
    out = nuclei_import._tool_nuclei_http(_Orch(), {"request": {
        "method": "GET", "path": ["/x"],
        "matchers": [{"type": "word", "condition": "and",
                      "words": ["hello", "absent"]}]},
        "template_id": "t"})
    assert out["verdict"] == "PASS"


def test_matcher_regex(monkeypatch):
    from engine import nuclei_import
    _install_client(monkeypatch, _Resp(200, "version 1.2.3"))
    out = nuclei_import._tool_nuclei_http(_Orch(), {"request": {
        "method": "GET", "path": ["/x"],
        "matchers": [{"type": "regex",
                      "regex": [r"version \d+\.\d+\.\d+"]}]},
        "template_id": "t"})
    assert out["verdict"] == "VULNERABLE"


def test_matcher_negative(monkeypatch):
    from engine import nuclei_import
    _install_client(monkeypatch, _Resp(200, "hello"))
    out = nuclei_import._tool_nuclei_http(_Orch(), {"request": {
        "method": "GET", "path": ["/x"],
        "matchers": [{"type": "word", "words": ["absent"],
                      "negative": True}]},
        "template_id": "t"})
    assert out["verdict"] == "VULNERABLE"


def test_no_path_returns_unknown(monkeypatch):
    from engine import nuclei_import
    _install_client(monkeypatch, _Resp(200, ""))
    out = nuclei_import._tool_nuclei_http(_Orch(), {"request": {
        "method": "GET"}, "template_id": "t"})
    assert out["verdict"] == "UNKNOWN"


def test_path_receives_base_url_substitution(monkeypatch):
    from engine import nuclei_import
    holder = _install_client(monkeypatch, _Resp(200, ""))
    nuclei_import._tool_nuclei_http(_Orch("https://real.test"), {"request": {
        "method": "GET", "path": ["{{BaseURL}}/api/v1/x"],
        "matchers": [{"type": "status", "status": [200]}]},
        "template_id": "t"})
    assert holder["c"].last["url"] == "https://real.test/api/v1/x"


def test_load_template_roundtrip(tmp_path):
    from engine import nuclei_import
    p = tmp_path / "t.yaml"
    p.write_text(textwrap.dedent("""\
        id: load-test
        info:
          name: LoadTest
          severity: low
        http:
          - method: GET
            path:
              - "{{BaseURL}}/a"
    """), encoding="utf-8")
    loaded = nuclei_import.load_template(str(p))
    assert loaded["id"] == "load-test"
    chain = nuclei_import.template_to_chain(loaded, str(p))
    assert chain["id"] == "nuclei-load-test"
    assert chain["priority"] == 300
