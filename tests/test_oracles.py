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


def test_header_absent_all_redirects_unknown(ctx, step):
    c = ctx(step('a', status=301, headers={}),
            step('b', status=302, headers={}))
    o = {'type': 'header_absent', 'headers': ['X-Frame-Options'],
         'verdict': 'VULNERABLE'}
    r = evaluate(o, c)
    assert r['verdict'] == 'UNKNOWN'
    assert 'redirect' in r['reason'].lower()


def test_header_absent_skips_redirect_step(ctx, step):
    c = ctx(step('redir', status=301, headers={}),
            step('real', status=200, headers={'X-Frame-Options': 'DENY'}))
    o = {'type': 'header_absent', 'headers': ['X-Frame-Options'],
         'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'PASS'


def test_header_absent_hsts_not_applicable_over_http(step):
    s = step('p', status=200, headers={'X-Content-Type-Options': 'nosniff'})
    s['url'] = 'http://insecure.test/api'
    c = {'steps': [s], 'inputs': {}, 'target': 'http://insecure.test'}
    o = {'type': 'header_absent',
         'headers': ['Strict-Transport-Security', 'X-Content-Type-Options'],
         'verdict': 'VULNERABLE'}
    r = evaluate(o, c)
    assert r['verdict'] == 'PASS'


def test_header_absent_hsts_required_over_https(step):
    s = step('p', status=200, headers={'X-Content-Type-Options': 'nosniff'})
    s['url'] = 'https://secure.test/api'
    c = {'steps': [s], 'inputs': {}, 'target': 'https://secure.test'}
    o = {'type': 'header_absent',
         'headers': ['Strict-Transport-Security', 'X-Content-Type-Options'],
         'verdict': 'VULNERABLE'}
    r = evaluate(o, c)
    assert r['verdict'] == 'VULNERABLE'
    assert 'strict-transport-security' in r['evidence']['missing']


def test_status_code_absent_all_redirects_unknown(ctx, step):
    c = ctx(step('a', status=301), step('b', status=308))
    o = {'type': 'status_code_absent', 'code': 429, 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'UNKNOWN'


def test_status_code_absent_all_404_unknown(ctx, step):
    c = ctx(step('a', status=404), step('b', status=404), step('c', status=405))
    o = {'type': 'status_code_absent', 'code': 429, 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'UNKNOWN'


def test_status_code_absent_real_absence_with_live_endpoint(ctx, step):
    c = ctx(step('a', status=200), step('b', status=200), step('c', status=404))
    o = {'type': 'status_code_absent', 'code': 429, 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'VULNERABLE'


HTML = {'content-type': 'text/html; charset=utf-8'}


def test_status_code_absent_soft404_unknown(step):
    neg = {'status': 200, 'is_html': True, 'json': False, 'size': 4006,
           'body_hash': 'deadbeefdeadbeef'}
    steps = [step('a', status=200, headers=HTML, body_hash='deadbeefdeadbeef'),
             step('b', status=200, headers=HTML, body_hash='deadbeefdeadbeef')]
    c = {'steps': steps, 'inputs': {}, 'target': 'x', 'negative_baseline': neg}
    o = {'type': 'status_code_absent', 'code': 429, 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'UNKNOWN'


def test_status_code_absent_identical_pages_unknown(step):
    steps = [step(n, status=200, headers=HTML, body='<html>same</html>')
             for n in ('a', 'b', 'c', 'd')]
    c = {'steps': steps, 'inputs': {}, 'target': 'x', 'negative_baseline': None}
    o = {'type': 'status_code_absent', 'code': 429, 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'UNKNOWN'


def test_status_code_absent_waf_html_only_unknown(step):
    steps = [step(n, status=403, headers=HTML, body=f'<html>blocked {n}</html>')
             for n in ('a', 'b', 'c', 'd')]
    c = {'steps': steps, 'inputs': {}, 'target': 'x', 'negative_baseline': None}
    o = {'type': 'status_code_absent', 'code': 429, 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'UNKNOWN'


def test_status_code_absent_json_login_still_vulnerable(step):
    JSONH = {'content-type': 'application/json'}
    steps = [step(n, status=400, headers=JSONH, body='{"error":"bad"}')
             for n in ('a', 'b', 'c', 'd')]
    c = {'steps': steps, 'inputs': {}, 'target': 'x', 'negative_baseline': None}
    o = {'type': 'status_code_absent', 'code': 429, 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'VULNERABLE'


def test_status_code_present_soft404_unknown(step):
    neg = {'status': 200, 'is_html': True, 'json': False, 'size': 4006,
           'body_hash': 'cafef00dcafef00d'}
    steps = [step('no_auth', status=200, headers=HTML, body_hash='cafef00dcafef00d'),
             step('bad_auth', status=200, headers=HTML, body_hash='cafef00dcafef00d')]
    c = {'steps': steps, 'inputs': {}, 'target': 'x', 'negative_baseline': neg}
    o = {'type': 'status_code_present', 'code': 200, 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'UNKNOWN'


def test_catchall_gates_behavioral_oracles(step):
    neg = {'status': 200, 'is_html': True, 'json': False, 'size': 361,
           'catch_all': True}
    steps = [step(n, status=403, headers=HTML, body=f'<html>blocked {n}</html>')
             for n in ('a', 'b', 'c')]
    c = {'steps': steps, 'inputs': {}, 'target': 'x', 'negative_baseline': neg}
    for otype in ('response_differs', 'state_inconsistent', 'timing_difference',
                  'expected_status_mismatch'):
        o = {'type': otype, 'verdict': 'SUSPICIOUS'}
        assert evaluate(o, c)['verdict'] == 'UNKNOWN', otype


def test_catchall_gate_skipped_for_json_api(step):
    from engine.oracle import _catch_all_blocks
    JSONH = {'content-type': 'application/json'}
    neg_on = {'catch_all': True, 'status': 200, 'is_html': True}
    json_steps = [step('a', status=200, headers=JSONH, body='{"a":1}')]
    assert _catch_all_blocks({'steps': json_steps, 'negative_baseline': neg_on}) is False
    html_steps = [step('a', status=403, headers={'content-type': 'text/html'}, body='x')]
    assert _catch_all_blocks({'steps': html_steps,
                              'negative_baseline': {'catch_all': False}}) is False
    assert _catch_all_blocks({'steps': html_steps, 'negative_baseline': neg_on}) is True


def test_status_code_present_idor_catchall_unknown(step):
    neg = {'status': 200, 'is_html': True, 'json': False, 'size': 4006,
           'body_hash': 'f00df00df00df00d'}
    steps = [step('baseline', status=200, headers=HTML, body='<html>'+('x'*26000)+'</html>'),
             step('id_1', status=200, headers=HTML, body_hash='f00df00df00df00d'),
             step('id_2', status=200, headers=HTML, body_hash='f00df00df00df00d'),
             step('id_99999', status=200, headers=HTML, body_hash='f00df00df00df00d')]
    c = {'steps': steps, 'inputs': {}, 'target': 'x', 'negative_baseline': neg}
    o = {'type': 'status_code_present', 'code': 200, 'verdict': 'SUSPICIOUS'}
    assert evaluate(o, c)['verdict'] == 'UNKNOWN'


def test_status_code_present_real_api_still_vulnerable(step):
    neg = {'status': 404, 'is_html': True, 'json': False, 'size': 500,
           'body_hash': 'aaaabbbbccccdddd'}
    steps = [step('no_auth', status=200,
                  headers={'content-type': 'application/json'}, body='{"id":1}')]
    c = {'steps': steps, 'inputs': {}, 'target': 'x', 'negative_baseline': neg}
    o = {'type': 'status_code_present', 'code': 200, 'verdict': 'VULNERABLE'}
    assert evaluate(o, c)['verdict'] == 'VULNERABLE'


def test_header_absent_recommended_only_is_downgraded(step):
    h = {'strict-transport-security': 'x', 'x-content-type-options': 'nosniff',
         'x-frame-options': 'DENY', 'content-security-policy': "default-src 'self'"}
    s = step('probe', status=200, headers=h)
    s['url'] = 'https://site.test'
    c = {'steps': [s], 'inputs': {}, 'target': 'x'}
    o = {'type': 'header_absent',
         'critical': ['Strict-Transport-Security', 'X-Content-Type-Options',
                      'X-Frame-Options', 'Content-Security-Policy'],
         'recommended': ['Referrer-Policy', 'Permissions-Policy'],
         'verdict': 'VULNERABLE', 'recommended_verdict': 'SUSPICIOUS'}
    r = evaluate(o, c)
    assert r['verdict'] == 'SUSPICIOUS'
    assert 'referrer-policy' in r['evidence']['missing_recommended']


def test_header_absent_missing_critical_is_vulnerable(step):
    h = {'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY',
         'referrer-policy': 'x', 'permissions-policy': 'x'}
    s = step('probe', status=200, headers=h)
    s['url'] = 'https://site.test'
    c = {'steps': [s], 'inputs': {}, 'target': 'x'}
    o = {'type': 'header_absent',
         'critical': ['Strict-Transport-Security', 'X-Content-Type-Options',
                      'X-Frame-Options', 'Content-Security-Policy'],
         'recommended': ['Referrer-Policy', 'Permissions-Policy'],
         'verdict': 'VULNERABLE', 'recommended_verdict': 'SUSPICIOUS'}
    r = evaluate(o, c)
    assert r['verdict'] == 'VULNERABLE'
    assert 'strict-transport-security' in r['evidence']['missing']


def _cors_ctx(step, acao, acac=None):
    h = {'access-control-allow-origin': acao}
    if acac is not None:
        h['access-control-allow-credentials'] = acac
    return {'steps': [step('probe', status=200, headers=h)],
            'inputs': {}, 'target': 'x', 'negative_baseline': None}


def test_cors_reflection_with_creds_vulnerable(step):
    c = _cors_ctx(step, 'https://attacker.example.com', 'true')
    o = {'type': 'cors_misconfig', 'test_origin': 'https://attacker.example.com'}
    assert evaluate(o, c)['verdict'] == 'VULNERABLE'


def test_cors_reflection_no_creds_vulnerable(step):
    c = _cors_ctx(step, 'https://attacker.example.com')
    o = {'type': 'cors_misconfig', 'test_origin': 'https://attacker.example.com'}
    assert evaluate(o, c)['verdict'] == 'VULNERABLE'


def test_cors_wildcard_only_passes(step):
    c = _cors_ctx(step, '*')
    o = {'type': 'cors_misconfig', 'test_origin': 'https://attacker.example.com'}
    assert evaluate(o, c)['verdict'] == 'PASS'


def test_cors_wildcard_with_creds_suspicious(step):
    c = _cors_ctx(step, '*', 'true')
    o = {'type': 'cors_misconfig', 'test_origin': 'https://attacker.example.com'}
    assert evaluate(o, c)['verdict'] == 'SUSPICIOUS'


def test_cors_no_header_passes(step):
    c = {'steps': [step('probe', status=200, headers={})],
         'inputs': {}, 'target': 'x', 'negative_baseline': None}
    o = {'type': 'cors_misconfig', 'test_origin': 'https://attacker.example.com'}
    assert evaluate(o, c)['verdict'] == 'PASS'


def test_semantic_diff_requires_two_steps(step):
    ctx = {'steps': [step('only', status=200)],
           'inputs': {}, 'target': 'x'}
    r = evaluate({'type': 'semantic_diff'}, ctx)
    assert r['verdict'] == 'UNKNOWN'
    assert 'two' in (r.get('reason') or '').lower() or \
           '2' in (r.get('reason') or '')


def test_semantic_diff_no_baseline_returns_unknown(step):
    s1 = step('s1', status=200, body='{"a":1}')
    s1['url'] = 'http://x/y'
    s2 = step('s2', status=200, body='{"a":2}')
    s2['url'] = 'http://x/y'
    ctx = {'steps': [s1, s2], 'inputs': {}, 'target': 'http://nonexistent'}
    r = evaluate({'type': 'semantic_diff'}, ctx)
    assert r['verdict'] == 'UNKNOWN'
    assert 'baseline' in (r.get('reason') or '').lower()


def test_annotate_with_signal_preserves_verdict():
    from engine.oracle import _annotate_with_signal
    result = {'verdict': 'VULNERABLE', 'reason': 'x', 'evidence': {'k': 1}}
    out = _annotate_with_signal(result, {'_signal_strength': 0.75})
    assert out['verdict'] == 'VULNERABLE'
    assert out['evidence']['signal_strength'] == 0.75
    assert out['evidence']['k'] == 1


def test_annotate_with_signal_no_context_returns_original():
    from engine.oracle import _annotate_with_signal
    result = {'verdict': 'PASS', 'evidence': {}}
    out = _annotate_with_signal(result, {})
    assert out is result


def test_annotate_with_signal_none_result():
    from engine.oracle import _annotate_with_signal
    assert _annotate_with_signal(None, {'_signal_strength': 0.5}) is None
