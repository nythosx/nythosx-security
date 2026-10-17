from engine.desync import queue_poison


def test_marker_is_unique():
    m1 = queue_poison._new_marker()
    m2 = queue_poison._new_marker()
    assert m1 != m2
    assert m1.startswith("qp-")
    assert len(m1) >= 10


def test_build_poison_prefix_contains_marker():
    prefix = queue_poison.build_poison_prefix(
        "http://127.0.0.1:9999/x", "marker123")
    assert b"marker123" in prefix
    assert b"Transfer-Encoding: chunked" in prefix
    assert b"X-Queue-Proof: marker123" in prefix


def test_build_victim_contains_marker():
    victim = queue_poison.build_victim_request(
        "http://127.0.0.1:9999/x", "marker456")
    assert b"marker456" in victim
    assert b"X-Queue-Proof-Client: marker456" in victim


def test_analyze_detects_poisoned_marker():
    reads = [
        {"headers_raw": b"HTTP/1.1 200 OK\r\nX-Queue-Proof: abc\r\n",
         "body_raw": b"queued-sneaky"},
        {"headers_raw": b"HTTP/1.1 200 OK\r\n", "body_raw": b"ok"},
    ]
    result = queue_poison._analyze_queue_response(reads, "abc", "ok")
    assert result["poisoned"] is True
    assert "response 0" in result["reason"]


def test_analyze_clean_sequence():
    reads = [
        {"headers_raw": b"HTTP/1.1 200 OK\r\n", "body_raw": b"ok"},
        {"headers_raw": b"HTTP/1.1 200 OK\r\nX-Queue-Proof: abc\r\n",
         "body_raw": b"ok"},
    ]
    result = queue_poison._analyze_queue_response(reads, "abc", "ok")
    assert result["poisoned"] is False


def test_analyze_no_marker_at_all():
    reads = [
        {"headers_raw": b"HTTP/1.1 200 OK\r\n", "body_raw": b"ok"},
    ]
    result = queue_poison._analyze_queue_response(reads, "xyz", "ok")
    assert result["poisoned"] is False
