from engine.baseline import BaselineEngine
from engine.diff import BaselineSnapshot

def test_cache_key_stable():
    e = BaselineEngine()
    k1 = e.cache_key("http://t", "http://t/api")
    k2 = e.cache_key("http://t", "http://t/api")
    assert k1 == k2
    assert "http" in k1

def test_save_and_load(tmp_path):
    e = BaselineEngine(cache_dir=tmp_path)
    snap = BaselineSnapshot(
        url="http://t/api", method="GET", status=200,
        body='{"ok":true}', body_len=11,
        timing_samples=[100.0, 105.0, 102.0],
    )
    e.save("http://t", snap)
    loaded = e.load("http://t", "http://t/api", "GET")
    assert loaded is not None
    assert loaded.status == 200
    assert loaded.body_len == 11
    assert len(loaded.timing_samples) == 3

def test_load_missing_returns_none(tmp_path):
    e = BaselineEngine(cache_dir=tmp_path)
    assert e.load("http://t", "http://t/x") is None

def test_acquire_returns_none_on_failure(monkeypatch):
    import engine.http as _http
    def boom(*a, **k):
        raise RuntimeError("network down")
    monkeypatch.setattr(_http, "Client", boom)
    e = BaselineEngine(samples=1)
    assert e.acquire("http://t/") is None
