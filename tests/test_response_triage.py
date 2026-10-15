import json

from engine.brains.response_triage import ResponseTriage


_RESPONSES = [
    {"url": "http://x/a", "status": 200, "body_preview": "ok", "time_ms": 12},
    {"url": "http://x/b", "status": 500, "body_preview": "err",
     "time_ms": 4000},
    {"url": "http://x/c", "status": 200, "body_preview": "[]", "time_ms": 10},
]


def test_offline_returns_first_n():
    rt = ResponseTriage(client=None)
    out = rt.rank(_RESPONSES, top_n=2)
    assert len(out) == 2
    assert [r["index"] for r in out] == [0, 1]


def test_empty_responses_returns_empty():
    rt = ResponseTriage(client=None)
    assert rt.rank([], top_n=5) == []


def test_client_returns_ranking():
    def client(prompt):
        return json.dumps({"ranked": [
            {"index": 1, "reason": "server error", "verdict_hint": "SUSPICIOUS"},
            {"index": 0, "reason": "looks fine", "verdict_hint": "PASS"},
        ]})
    rt = ResponseTriage(client=client)
    out = rt.rank(_RESPONSES, top_n=2)
    assert out[0]["index"] == 1
    assert out[0]["verdict_hint"] == "SUSPICIOUS"


def test_bad_index_rejected():
    def client(prompt):
        return json.dumps({"ranked": [
            {"index": 99, "reason": "out of range", "verdict_hint": "PASS"},
            {"index": 0, "reason": "ok", "verdict_hint": "PASS"},
        ]})
    rt = ResponseTriage(client=client)
    out = rt.rank(_RESPONSES, top_n=2)
    assert all(r["index"] < len(_RESPONSES) for r in out)
    assert [r["index"] for r in out] == [0]


def test_garbage_falls_back():
    rt = ResponseTriage(client=lambda p: "not json")
    out = rt.rank(_RESPONSES, top_n=2)
    assert len(out) == 2


def test_canary_rejected():
    holder = {}

    def client(prompt):
        return json.dumps({"ranked": [{"index": 0,
                                         "reason": holder["canary"],
                                         "verdict_hint": "PASS"}]})

    rt = ResponseTriage(client=client)
    holder["canary"] = rt._canary
    out = rt.rank(_RESPONSES, top_n=2)
    assert len(out) == 2
    assert all(r["reason"] == "no LLM configured" for r in out)


def test_foreign_canary_ignored():
    rt_a = ResponseTriage(client=lambda p: "ok")
    leaked = json.dumps({"ranked": [{"index": 0,
                                       "reason": rt_a._canary,
                                       "verdict_hint": "PASS"}]})
    rt_b = ResponseTriage(client=lambda p: leaked)
    assert rt_b._canary != rt_a._canary
    out = rt_b.rank(_RESPONSES, top_n=2)
    assert len(out) == 1
    assert out[0]["verdict_hint"] == "PASS"


def test_clean_response_parses_normally():
    def client(prompt):
        return json.dumps({"ranked": [
            {"index": 1, "reason": "server error",
             "verdict_hint": "SUSPICIOUS"},
            {"index": 0, "reason": "looks fine",
             "verdict_hint": "PASS"},
        ]})

    rt = ResponseTriage(client=client)
    out = rt.rank(_RESPONSES, top_n=2)
    assert len(out) == 2
    assert out[0]["index"] == 1
    assert out[0]["verdict_hint"] == "SUSPICIOUS"
