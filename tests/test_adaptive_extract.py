import json


class FakeResponse:
    def __init__(self, status_code=200, body="", url="http://test/",
                 content_type="application/json"):
        self.status_code = status_code
        self.text = body
        self.url = url
        self.headers = {"Content-Type": content_type}
        self.cookies = {}
        self.elapsed = None

    def json(self):
        return json.loads(self.text)


class FakeClient:
    def __init__(self, queue, idx):
        self._queue = queue
        self._idx = idx

    def get(self, url, **kw):
        return self._next()

    def post(self, url, **kw):
        return self._next()

    def request(self, method, url, **kw):
        return self._next()

    def _next(self):
        if self._idx[0] >= len(self._queue):
            return FakeResponse(404, "")
        r = self._queue[self._idx[0]]
        self._idx[0] += 1
        return r

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _install_fake(monkeypatch, responses):
    from engine import http as _http
    queue = list(responses)
    idx = [0]

    def _ctor(*a, **kw):
        return FakeClient(queue, idx)

    monkeypatch.setattr(_http, "Client", _ctor)
    return idx


def test_pagination_probe_respects_max_pages(monkeypatch):
    from engine import data_extractor
    responses = [
        FakeResponse(200, json.dumps({"data": [{"id": i}]}))
        for i in range(20)
    ]
    _install_fake(monkeypatch, responses)
    result = data_extractor.extract_with_pagination(
        "http://test/api", max_pages=3, mode="probe"
    )
    assert result["pages_fetched"] == 3


def test_pagination_harvest_extends_beyond_max_pages(monkeypatch):
    from engine import data_extractor
    responses = [
        FakeResponse(200, json.dumps({"data": [{"id": i}]}))
        for i in range(20)
    ]
    _install_fake(monkeypatch, responses)
    result = data_extractor.extract_with_pagination(
        "http://test/api", max_pages=3, mode="harvest", hard_ceiling=10
    )
    assert result["pages_fetched"] == 10


def test_pagination_harvest_writes_to_artifacts(monkeypatch, tmp_path):
    from engine import data_extractor, artifacts
    monkeypatch.setattr(artifacts, "ARTIFACT_DIR", tmp_path)
    monkeypatch.delenv("EVIDENCE_KEY", raising=False)
    responses = [
        FakeResponse(200, json.dumps({"data": [{"id": i}]}))
        for i in range(5)
    ]
    _install_fake(monkeypatch, responses)
    data_extractor.extract_with_pagination(
        "http://test/api", max_pages=3, mode="harvest", hard_ceiling=3,
        target="page-test.local"
    )
    entries = artifacts.load_for("page-test.local")
    assert len(entries) >= 3


def test_pagination_probe_does_not_write_artifacts(monkeypatch, tmp_path):
    from engine import data_extractor, artifacts
    monkeypatch.setattr(artifacts, "ARTIFACT_DIR", tmp_path)
    monkeypatch.delenv("EVIDENCE_KEY", raising=False)
    responses = [
        FakeResponse(200, json.dumps({"data": [{"id": i}]}))
        for i in range(5)
    ]
    _install_fake(monkeypatch, responses)
    data_extractor.extract_with_pagination(
        "http://test/api", max_pages=3, mode="probe",
        target="page-probe.local"
    )
    entries = artifacts.load_for("page-probe.local")
    assert entries == []


def test_bola_probe_respects_max_records(monkeypatch):
    from engine import bola_scanner
    responses = [
        FakeResponse(200, json.dumps({"id": i, "owner_id": "u1"}))
        for i in range(20)
    ]
    _install_fake(monkeypatch, responses)
    result = bola_scanner.harvest_sequential_ids(
        "http://test", "/api/orders/{id}", "tok",
        max_records=3, mode="probe"
    )
    assert len(result) == 3


def test_bola_harvest_goes_further(monkeypatch):
    from engine import bola_scanner
    responses = [
        FakeResponse(200, json.dumps({"id": i, "owner_id": "u1"}))
        for i in range(20)
    ]
    _install_fake(monkeypatch, responses)
    result = bola_scanner.harvest_sequential_ids(
        "http://test", "/api/orders/{id}", "tok",
        max_records=3, mode="harvest", hard_ceiling=10
    )
    assert len(result) == 10


def test_bola_harvest_stops_on_403(monkeypatch):
    from engine import bola_scanner
    responses = [
        FakeResponse(200, json.dumps({"id": 1, "owner_id": "u1"})),
        FakeResponse(200, json.dumps({"id": 2, "owner_id": "u1"})),
        FakeResponse(403, ""),
    ]
    _install_fake(monkeypatch, responses)
    result = bola_scanner.harvest_sequential_ids(
        "http://test", "/api/orders/{id}", "tok",
        max_records=3, mode="harvest", hard_ceiling=10
    )
    assert len(result) == 2


def test_bola_harvest_writes_to_artifacts(monkeypatch, tmp_path):
    from engine import bola_scanner, artifacts
    monkeypatch.setattr(artifacts, "ARTIFACT_DIR", tmp_path)
    monkeypatch.delenv("EVIDENCE_KEY", raising=False)
    responses = [
        FakeResponse(200, json.dumps({"id": i, "owner_id": "u1"}))
        for i in range(5)
    ]
    _install_fake(monkeypatch, responses)
    bola_scanner.harvest_sequential_ids(
        "http://test", "/api/orders/{id}", "tok",
        max_records=2, mode="harvest", hard_ceiling=4,
        target="bola-test.local"
    )
    entries = artifacts.load_for("bola-test.local")
    assert len(entries) >= 4


def test_blind_extract_probe_caps_at_max_length(monkeypatch):
    from engine import blind_extract
    def fake_send(*a, **kw):
        return {"status": 200, "body": "", "elapsed_ms": 5000}
    monkeypatch.setattr(blind_extract, "_send", fake_send)
    result = blind_extract.extract_string(
        "http://x", "q", "users", "password", dbms="mysql",
        max_length=3, max_requests=100, mode="probe"
    )
    assert len(result["extracted"]) <= 3


def test_blind_extract_harvest_extends_length(monkeypatch):
    from engine import blind_extract
    def fake_send(*a, **kw):
        return {"status": 200, "body": "", "elapsed_ms": 5000}
    monkeypatch.setattr(blind_extract, "_send", fake_send)
    result = blind_extract.extract_string(
        "http://x", "q", "users", "password", dbms="mysql",
        max_length=3, max_requests=100, mode="harvest",
        extended_max_length=5, hard_ceiling=500
    )
    assert len(result["extracted"]) <= 5
