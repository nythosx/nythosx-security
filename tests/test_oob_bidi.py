import time


def _server():
    from engine.oob import OOBServer
    s = OOBServer(port=0).start()
    return s


class _NullClient:
    def request(self, *a, **kw):
        return None

    def get(self, *a, **kw):
        return None

    def post(self, *a, **kw):
        return None

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeOOB:
    def __init__(self, command_output=b"uid=0(root) gid=0(root) groups=0(root)"):
        self.base_url = "http://oob.local"
        self.is_external = False
        self._cmd_out = command_output
        self._n = 0

    def payload_url(self, token=None):
        self._n += 1
        t = token or ("tok%d" % self._n)
        return t, "http://oob.local/" + t

    def interactions(self, token):
        if self.hit_count(token) <= 0:
            return []
        body = self._cmd_out or b""
        return [{
            "token": token,
            "method": "GET",
            "path": "/" + token,
            "client": "127.0.0.1",
            "time": 0.0,
            "body": body,
            "body_text": body.decode("utf-8", "replace"),
        }]

    def hit_count(self, token):
        return 1

    def poll_output(self, token):
        return self._cmd_out

    def output_for(self, token):
        return self._cmd_out

    def clear_output(self, token):
        pass

    def wait_for_hit(self, token, timeout=5.0, poll=0.1):
        return True

    def wait_for_output(self, token, timeout=5.0, poll=0.1):
        return True

    def send_command(self, token, cmd):
        return True

    def stop(self):
        pass


def test_send_command_and_pop():
    from engine.oob import OOBServer
    s = OOBServer(port=0)
    s.send_command("tok", "id")
    s.send_command("tok", "whoami")
    assert s._pop_command("tok") == "id"
    assert s._pop_command("tok") == "whoami"
    assert s._pop_command("tok") is None


def test_poll_output_empty():
    from engine.oob import OOBServer
    s = OOBServer(port=0)
    assert s.poll_output("missing") == b""
    assert s.output_for("missing") == b""


def test_clear_output():
    from engine.oob import OOBServer
    s = OOBServer(port=0)
    s._add_output("tok", b"data")
    assert s.poll_output("tok") == b"data"
    s.clear_output("tok")
    assert s.poll_output("tok") == b""


def test_looks_like_command_output_positive():
    from engine.oob import looks_like_command_output
    assert looks_like_command_output("uid=0(root) gid=0(root) groups=0(root)")
    assert looks_like_command_output("uid=33(www-data) gid=33")
    assert looks_like_command_output("root:x:0:0:root:/root:/bin/bash")


def test_looks_like_command_output_negative():
    from engine.oob import looks_like_command_output
    assert looks_like_command_output("") is False
    assert looks_like_command_output("hello world") is False
    assert looks_like_command_output('{"ok":true}') is False


def test_real_http_output_capture():
    import httpx
    s = _server()
    try:
        base = s.base_url
        token, _url = s.payload_url()
        r = httpx.post(
            base + "/" + token,
            content=b"uid=0(root) gid=0(root) groups=0(root)",
            timeout=5,
        )
        assert r.status_code == 200
        assert s.wait_for_output(token, timeout=2.0)
        body = s.poll_output(token)
        assert b"uid=0" in body
    finally:
        s.stop()


def test_real_http_command_dispatch():
    import httpx
    s = _server()
    try:
        base = s.base_url
        token, _url = s.payload_url()
        s.send_command(token, "whoami")
        r = httpx.get(base + "/" + token + "/next", timeout=5)
        assert r.status_code == 200
        assert r.text == "whoami"
        r2 = httpx.get(base + "/" + token + "/next", timeout=5)
        assert r2.status_code == 204
    finally:
        s.stop()


def test_stop_clears_state():
    s = _server()
    token, _url = s.payload_url()
    s._add_output(token, b"x")
    s.send_command(token, "cmd")
    s.stop()
    assert s.poll_output(token) == b""
    assert s._pop_command(token) is None


def test_ssrf_marks_code_executed_when_output_present(monkeypatch):
    from engine import ssrf
    monkeypatch.setattr(ssrf, "_make_client",
                        lambda *a, **kw: _NullClient())
    monkeypatch.setattr(ssrf, "_wait_any",
                        lambda oob, tokens, timeout: True)
    out = ssrf.probe("https://x.test/api",
                     oob_server=_FakeOOB(), params=["url"])
    inner = out["result"]
    assert inner["outcome"] == "CODE_EXECUTED"
    assert out.outcome.value == "CODE_EXECUTED"
    assert "rce_tokens" in inner["evidence"]


def test_ssrf_no_rce_when_output_is_generic(monkeypatch):
    from engine import ssrf
    monkeypatch.setattr(ssrf, "_make_client",
                        lambda *a, **kw: _NullClient())
    monkeypatch.setattr(ssrf, "_wait_any",
                        lambda oob, tokens, timeout: True)
    out = ssrf.probe("https://x.test/api",
                     oob_server=_FakeOOB(command_output=b"ok"),
                     params=["url"])
    inner = out["result"]
    assert inner["verdict"] == "VULNERABLE"
    assert inner.get("outcome") != "CODE_EXECUTED"
