import pytest


def test_modules_import():
    from engine import (weak_password_policy, lockout_probe,
                        weak_credential_enum)
    assert weak_password_policy is not None
    assert lockout_probe is not None
    assert weak_credential_enum is not None


class _Refused:
    def __init__(self, *a, **kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def request(self, *a, **kw):
        import httpx
        raise httpx.ConnectError("refused")

    def get(self, *a, **kw):
        import httpx
        raise httpx.ConnectError("refused")

    def post(self, *a, **kw):
        import httpx
        raise httpx.ConnectError("refused")


def test_scan_returns_scanresult(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "Client", _Refused)

    from engine import weak_password_policy
    from engine.contract import ScanResult
    r = weak_password_policy.scan("http://127.0.0.1:1")
    assert isinstance(r, ScanResult)
    assert r["verdict"] in ("UNKNOWN", "PASS", "VULNERABLE", "SUSPICIOUS")
    assert r.capability == "weak_password_scan"


def test_lockout_probe_idempotent_false():
    from engine import lockout_probe
    assert lockout_probe.CAPABILITY.idempotent is False
    assert lockout_probe.CAPABILITY.default_on is False


def test_weak_credential_enum_destructive():
    from engine import weak_credential_enum
    assert weak_credential_enum.CAPABILITY.destructive is True
    assert weak_credential_enum.CAPABILITY.default_on is False


def test_weak_credential_enum_disabled_by_default():
    from engine import weak_credential_enum
    r = weak_credential_enum.scan("http://127.0.0.1:1")
    assert r["verdict"] == "UNKNOWN"
    assert "disabled" in r.reason.lower() or "opt_in" in r.reason.lower()
