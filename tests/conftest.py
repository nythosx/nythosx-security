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


@pytest.fixture
def scan_result():
    def _make(capability='demo_scan', target='http://test', verdict='VULNERABLE',
              severity='high', reason='demo finding', evidence=None):
        from engine.contract import ScanResult
        return ScanResult(
            capability=capability, target=target, verdict=verdict,
            severity=severity, reason=reason, evidence=evidence or {},
        )
    return _make


@pytest.fixture
def finding_row():
    def _make(pattern_id='env-file-exposure', verdict='VULNERABLE',
              severity='high', reason='/.env served', evidence_path='',
              wstg_id='WSTG-CONF-02', cwe_id='CWE-538', fid=1):
        return {
            'id': fid, 'timestamp': '2026-10-10T00:00:00Z',
            'pattern_id': pattern_id, 'category': 'content', 'verdict': verdict,
            'severity': severity, 'reason': reason, 'wstg_id': wstg_id,
            'cwe_id': cwe_id, 'evidence_path': evidence_path, 'duration_ms': 5,
        }
    return _make


@pytest.fixture
def mock_chains():
    return [
        {
            'id': 'laravel-admin-takeover', 'name': 'Laravel Admin Takeover',
            'verdict': 'CONFIRMED', 'severity': 'critical', 'confidence': 0.85,
            'prerequisites': ['env-file-exposure', 'mass-assignment'],
            'matched': [{'pattern_id': 'env-file-exposure', 'verdict': 'VULNERABLE'},
                        {'pattern_id': 'mass-assignment', 'verdict': 'VULNERABLE'}],
            'missing': [], 'steps': [], 'narrative_text': 'Step 1 -> Step 2',
        },
    ]
