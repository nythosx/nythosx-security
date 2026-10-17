import httpx

from engine import external_http


def test_client_wraps_httpx_client():
    import httpx
    with external_http.Client(timeout=1) as c:
        assert isinstance(c._inner, httpx.Client)


def test_async_client_wraps_httpx_client():
    import asyncio
    import httpx

    async def go():
        async with external_http.AsyncClient(timeout=1) as c:
            return isinstance(c._inner, httpx.AsyncClient)

    assert asyncio.run(go()) is True


def test_circuit_open_is_connect_error():
    from engine import external_http as m
    assert issubclass(m.ExternalCircuitOpen, httpx.ConnectError)


def test_breaker_opens_after_threshold():
    from engine import external_http as m
    m.reset_breaker_state()
    for _ in range(m.CIRCUIT_THRESHOLD):
        m._breaker_fail("nvd.test")
    assert m._breaker_allow("nvd.test") is False
    snapshot = m.breaker_snapshot()
    assert snapshot["nvd.test"]["failures"] == m.CIRCUIT_THRESHOLD
    m.reset_breaker_state()
    assert m._breaker_allow("nvd.test") is True


def test_breaker_resets_on_success():
    from engine import external_http as m
    m.reset_breaker_state()
    m._breaker_fail("osv.test")
    m._breaker_fail("osv.test")
    m._breaker_ok("osv.test")
    snapshot = m.breaker_snapshot()
    assert snapshot["osv.test"]["failures"] == 0


def test_client_instantiation():
    with external_http.Client(timeout=1) as c:
        assert c is not None


def test_async_client_instantiation():
    import asyncio

    async def go():
        async with external_http.AsyncClient(timeout=1) as c:
            return c is not None

    assert asyncio.run(go()) is True
