import pytest
from engine.roe_guard import ROEGuard, ROEViolation


ROE = {
    'enabled': True,
    'scope': {
        'in_scope': ['localhost', '127.0.0.1'],
        'out_of_scope': ['*.gov'],
        'allowed_methods': ['GET', 'POST'],
        'forbidden_paths': ['/admin', '/api/*/drop'],
    }
}


def test_in_scope_allowed():
    g = ROEGuard(ROE)
    assert g.check_url('http://localhost/api/me', 'GET')


def test_out_of_scope_blocked():
    g = ROEGuard(ROE)
    with pytest.raises(ROEViolation):
        g.check_url('http://evil.gov/api', 'GET')


def test_not_in_scope_blocked():
    g = ROEGuard(ROE)
    with pytest.raises(ROEViolation):
        g.check_url('http://example.com/', 'GET')


def test_method_blocked():
    g = ROEGuard(ROE)
    with pytest.raises(ROEViolation):
        g.check_url('http://localhost/api', 'DELETE')


def test_forbidden_literal():
    g = ROEGuard(ROE)
    with pytest.raises(ROEViolation):
        g.check_url('http://localhost/admin', 'GET')


def test_forbidden_glob():
    g = ROEGuard(ROE)
    with pytest.raises(ROEViolation):
        g.check_url('http://localhost/api/v1/drop', 'POST')


def test_fail_closed_missing_scope():
    g = ROEGuard({'enabled': True})
    with pytest.raises(ROEViolation):
        g.check_url('http://localhost/', 'GET')


def test_disabled_allows_all():
    g = ROEGuard({'enabled': False})
    assert g.check_url('http://anything.example/', 'GET')
