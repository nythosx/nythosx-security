import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(ROOT))

import pytest


@pytest.fixture
def step():
    def _make(name='step', status=200, body='', headers=None,
              time_ms=10.0, body_hash=None):
        if body_hash is None:
            import hashlib
            body_hash = hashlib.sha256(
                body.encode('utf-8', 'ignore')).hexdigest()[:16]
        return {
            'step_name': name,
            'status': status,
            'body': body,
            'headers': headers or {},
            'time_ms': time_ms,
            'body_hash': body_hash,
            'url': 'http://test/' + name,
        }
    return _make


@pytest.fixture
def ctx(step):
    def _make(*steps):
        return {'steps': list(steps), 'inputs': {}, 'target': 'http://test'}
    return _make
