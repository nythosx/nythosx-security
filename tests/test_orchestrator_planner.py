import json

from engine import llm_service
from engine import http as _http
from engine.chain_engine import ChainOrchestrator


def _orch():
    return ChainOrchestrator("http://127.0.0.1", job_id=None)


class _FakeResp:
    def __init__(self, status=200, text="ok"):
        self.status_code = status
        self.text = text


class _FakeClient:
    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def request(self, method, url, **k):
        return _FakeResp(200, '{"ok":true}')


def _planner_client(steps):
    it = iter(steps)

    def client(prompt):
        try:
            return json.dumps(next(it))
        except StopIteration:
            return json.dumps({"stop": True})
    return client


def test_planner_phase_noop_without_ai(monkeypatch):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    orch = _orch()
    orch._run_planner_phase()
    assert "planner_trace" not in orch.recon


def test_planner_phase_runs_bounded(monkeypatch):
    monkeypatch.setattr(_http, "Client", _FakeClient)
    steps = [{"method": "GET", "url": "http://127.0.0.1/api/v1/users",
              "reason": "enumerate"},
             {"method": "GET", "url": "http://127.0.0.1/api/v1/admin",
              "reason": "check admin"}]
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: _planner_client(steps))
    orch = _orch()
    orch._run_planner_phase()
    assert orch.recon.get("planner_trace")
    assert len(orch.recon["planner_trace"]) == 2
    assert orch.recon["planner_trace"][0]["status"] == 200


def test_planner_phase_rejects_off_host(monkeypatch):
    monkeypatch.setattr(_http, "Client", _FakeClient)
    steps = [{"method": "GET", "url": "http://evil.example.com/steal",
              "reason": "exfil"}]
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: _planner_client(steps))
    orch = _orch()
    orch._run_planner_phase()
    assert "planner_trace" not in orch.recon


def test_planner_phase_rejects_write_method(monkeypatch):
    monkeypatch.setattr(_http, "Client", _FakeClient)
    steps = [{"method": "DELETE", "url": "http://127.0.0.1/api/v1/users/1",
              "reason": "delete"}]
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: _planner_client(steps))
    orch = _orch()
    orch._run_planner_phase()
    assert "planner_trace" not in orch.recon
