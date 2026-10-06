from engine.oracle import evaluate


def test_pattern_match_multi_step(ctx, step):
    c = ctx(step('a', body='SECRET_KEY=abc'),
            step('b', body='nothing'))
    o = {'type': 'pattern_match', 'regex': r'SECRET_KEY=',
         'verdict': 'VULNERABLE'}
    r = evaluate(o, c)
    assert r['verdict'] == 'VULNERABLE'
    assert r['evidence']['matched_step'] == 'a'


def test_pattern_match_no_match(ctx, step):
    c = ctx(step('a', body='nothing'), step('b', body='also nothing'))
    o = {'type': 'pattern_match', 'regex': r'SECRET_KEY=',
         'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'PASS'


def test_status_code_absent_all_error(ctx, step):
    c = ctx(step('a', status=None), step('b', status=None))
    o = {'type': 'status_code_absent', 'code': 429,
         'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'UNKNOWN'


def test_status_code_absent_all_5xx(ctx, step):
    c = ctx(step('a', status=500), step('b', status=502))
    o = {'type': 'status_code_absent', 'code': 429,
         'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'UNKNOWN'


def test_status_code_absent_real_absence(ctx, step):
    c = ctx(step('a', status=200), step('b', status=401))
    o = {'type': 'status_code_absent', 'code': 429,
         'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'VULNERABLE'


def test_header_absent_multi_step(ctx, step):
    c = ctx(step('a', headers={'X-Frame-Options': 'DENY'}),
            step('b', headers={}))
    o = {'type': 'header_absent', 'headers': ['X-Frame-Options'],
         'verdict': 'VULNERABLE'}
    r = evaluate(o, c)
    assert r['verdict'] == 'VULNERABLE'
    assert r['evidence']['step'] == 'b'


def test_header_value_match_scans_all_steps(ctx, step):
    c = ctx(step('a', headers={}),
            step('b', headers={'Access-Control-Allow-Origin': '*'}))
    o = {'type': 'header_value_match',
         'header': 'Access-Control-Allow-Origin',
         'regex': r'\*', 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'VULNERABLE'


def test_no_auth_200(ctx, step):
    c = ctx(step('no_auth', status=200), step('bad', status=401))
    o = {'type': 'no_auth_200', 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'VULNERABLE'
