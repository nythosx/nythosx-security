import threading

from engine.http import CircuitBreaker, _get_breaker


def test_breaker_is_not_none_at_import():
    b = _get_breaker()
    assert b is not None
    assert isinstance(b, CircuitBreaker)


def test_breaker_is_singleton():
    assert _get_breaker() is _get_breaker()


def test_breaker_concurrent_init_single_instance():
    results = []
    lock = threading.Lock()

    def grab():
        b = _get_breaker()
        with lock:
            results.append(id(b))

    threads = [threading.Thread(target=grab) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(set(results)) == 1


def test_per_host_state_independent():
    b = _get_breaker()
    for _ in range(10):
        b.record_failure("host-a")
    assert not b.allow("host-a")
    assert b.allow("host-b")
    b.record_success("host-a")
    assert b.allow("host-a")


def test_breaker_threshold_from_config():
    b = _get_breaker()
    assert b.threshold >= 1
    assert b.cooldown_seconds > 0
