"""The server: login, throttle, cross-site protection, the fixed command list, input checks, push subscriptions (no SSRF), headers."""
import json, time
import pytest
from app.main import create_app, push_host_ok

PW = 'ein-langes-passwort'
H = {'X-Requested-With': 'sarah', 'Content-Type': 'application/json'}


@pytest.fixture
def ctx(fw, tmp_path):
    env = {'UI_PASSWORD': PW, 'OPNSENSE_URL': fw.url, 'OPNSENSE_KEY': fw.key, 'OPNSENSE_SECRET': fw.secret, 'DATA_DIR': str(tmp_path / 'data'), 'PUSH_ALLOW_ANY': '0'}
    app = create_app(env, start_poller=False)
    return app, app.test_client(), fw


def login(c, pw=PW):
    return c.post('/api/login', json={'password': pw}, headers={'X-Requested-With': 'sarah'})


def post(c, path, data=None):
    return c.post(path, data=json.dumps(data or {}), headers=H)


@pytest.fixture
def cli(ctx):
    app, c, fw = ctx
    assert login(c).status_code == 200
    return c, fw, app


def test_it_refuses_to_start_without_a_password_or_a_firewall(fw, tmp_path):
    base = {'OPNSENSE_URL': fw.url, 'OPNSENSE_KEY': 'k', 'OPNSENSE_SECRET': 's', 'DATA_DIR': str(tmp_path)}
    for bad in ({'UI_PASSWORD': ''}, {'UI_PASSWORD': 'kurz'}, {'UI_PASSWORD': PW, 'OPNSENSE_URL': ''}, {'UI_PASSWORD': PW, 'OPNSENSE_KEY': ''}):
        with pytest.raises(RuntimeError):
            create_app(dict(base, **bad), start_poller=False)


def test_nothing_works_without_login(ctx):
    app, c, fw = ctx
    assert c.get('/healthz').status_code == 200
    for path in ('/api/state', '/api/tasks', '/api/inv', '/api/prefs'):
        assert c.get(path).status_code == 401, path
    for path in ('/api/analyze', '/api/task', '/api/do', '/api/noaus', '/api/prefs', '/api/push/test', '/api/pin/trust'):
        assert c.post(path, json={}, headers={'X-Requested-With': 'sarah'}).status_code == 401, path
    assert fw.calls == [], 'not a single request reached the firewall'


def test_login(ctx):
    app, c, fw = ctx
    assert c.post('/api/login', json={'password': PW}).status_code == 403, 'a cross-site form cannot send the header'
    assert login(c, 'falsch').status_code == 401
    r = login(c)
    assert r.status_code == 200 and c.get('/api/me').get_json()['login'] is True
    cookie = r.headers['Set-Cookie']
    assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie and 'Secure' not in cookie, 'plain http (a local trial) works'
    assert 'Secure' in c.post('/api/login', json={'password': PW}, headers={'X-Requested-With': 'sarah'}, base_url='https://sarah.example').headers['Set-Cookie']
    c.post('/api/logout', headers=H)
    assert c.get('/api/me').get_json()['login'] is False


def test_five_wrong_passwords_lock_the_door_for_a_minute_and_it_doubles(ctx):
    app, c, fw = ctx
    th = app.extensions['sarah']['throttle']
    clock = [1000.0]
    th.clock = lambda: clock[0]
    for _ in range(5):
        assert login(c, 'x').status_code == 401
    r = login(c)
    assert r.status_code == 429 and 55 <= r.get_json()['wait'] <= 60, 'even the right password has to wait'
    clock[0] += 61
    for _ in range(5):                                     # no success in between: the next lock is twice as long
        assert login(c, 'x').status_code == 401
    r = login(c)
    assert r.status_code == 429 and 115 <= r.get_json()['wait'] <= 120
    clock[0] += 61
    assert login(c).status_code == 429, 'a minute is no longer enough'
    clock[0] += 61
    assert login(c).status_code == 200, 'after two minutes it works again'
    c.post('/api/logout', headers=H)
    for _ in range(5):
        login(c, 'x')
    clock[0] += 61
    assert login(c).status_code == 200, 'a successful login forgets the penalty: the lock starts again at one minute'


def test_state_comes_from_the_firewall_and_never_contains_a_secret(cli):
    c, fw, app = cli
    d = c.get('/api/state').get_json()
    assert d['status']['level'] == 'calm' and d['stale'] is False and d['pin']['fp'].count(':') == 31 and d['push']['key'] and d['host'] == '127.0.0.1'
    text = json.dumps(d)
    assert fw.key not in text and fw.secret not in text and PW not in text


def test_state_survives_a_dead_firewall_with_the_last_known_data(cli):
    c, fw, app = cli
    c.get('/api/state')
    fw.mode = 'drop'
    app.extensions['sarah']['poller'].st_t = 0
    d = c.get('/api/state').get_json()
    assert d['stale'] is True and d['kind'] == 'offline' and d['status']['level'] == 'calm' and d['health']['ok'] is False


def test_state_is_cached_for_a_few_seconds(cli):
    c, fw, app = cli
    c.get('/api/state'); n = len(fw.calls)
    c.get('/api/state'); c.get('/api/state')
    assert len(fw.calls) == n, 'a busy page does not hammer the firewall'


def test_cross_site_protection_on_every_change(cli):
    c, fw, app = cli
    for path in ('/api/analyze', '/api/task', '/api/do', '/api/dismiss', '/api/release', '/api/inv/now', '/api/noaus', '/api/prefs', '/api/push/subscribe', '/api/push/test'):
        assert c.post(path, json={}).status_code == 403, path + ' without the header'
        assert c.post(path, data='x=1', headers={'X-Requested-With': 'sarah'}).status_code == 403, path + ' as a form'
    assert [x for x in fw.calls if x[0] == 'POST'] == []


def test_only_the_fixed_commands_exist(cli):
    c, fw, app = cli
    for path in ('/api/set', '/api/setkey', '/api/delkey', '/api/off', '/api/test', '/api/models', '/api/preview', '/api/apitest', '/api/cmd', '/api/', '/api/proxy',
                 '/api/scdeck/stats/sarah', '/../app/main.py', '/%2e%2e/app/main.py', '/app/main.py'):
        assert c.post(path, json={}, headers=H).status_code in (404, 405) and c.get(path).status_code in (404, 405), path
    assert fw.calls == []


def test_commands_and_their_input_checks(cli):
    c, fw, app = cli
    assert post(c, '/api/task', {'text': 'Prüfe, warum die Kamera Probleme macht'}).get_json()['ok']
    assert ('POST', 'task', 'Prüfe, warum die Kamera Probleme macht') in fw.calls
    bad = [('/api/task', {'text': ''}), ('/api/task', {'text': 'x' * 1001}), ('/api/task', {}), ('/api/inv/now', {'ip': 'abc'}), ('/api/inv/now', {'ip': '1.2.3.4;ls'}),
           ('/api/do', {'id': 'dns:evil'}), ('/api/do', {'id': 'x' * 100}), ('/api/dismiss', {'id': ''}), ('/api/release', {'id': 'abc'})]
    n = len(fw.calls)
    for path, data in bad:
        r = post(c, path, data)
        assert r.status_code == 400 and r.get_json()['kind'] == 'input', (path, data, r.get_json())
    assert len(fw.calls) == n, 'invalid input never reached the firewall'
    assert post(c, '/api/inv/now', {'ip': '192.168.1.90'}).get_json()['ok'] and ('POST', 'invnow', '192.168.1.90') in fw.calls
    r = post(c, '/api/release', {'id': 7})
    assert ('POST', 'release', '7') in fw.calls and r.get_json()['kind'] == 'firewall', 'a JSON number is a valid id; the firewall itself answers'


def test_the_firewalls_own_refusal_is_passed_on(cli):
    c, fw, app = cli
    r = post(c, '/api/do', {'id': 'dns:doh'})
    assert r.status_code == 400 and 'gilt nicht mehr' in r.get_json()['error'] and r.get_json()['kind'] == 'firewall'


def test_a_dead_firewall_is_a_502_with_a_cause(cli):
    c, fw, app = cli
    fw.mode = 'drop'
    r = post(c, '/api/analyze')
    assert r.status_code == 502 and r.get_json()['kind'] == 'offline'


def test_not_aus_needs_a_confirmation(cli):
    c, fw, app = cli
    assert post(c, '/api/noaus', {}).status_code == 400 and post(c, '/api/noaus', {'confirm': 'yes'}).status_code == 400
    assert not [x for x in fw.calls if x[1] == 'noaus']
    assert post(c, '/api/noaus', {'confirm': True}).get_json()['ok'] and ('POST', 'noaus', None) in fw.calls


def test_preferences_are_checked(cli):
    c, fw, app = cli
    assert c.get('/api/prefs').get_json()['level'] == 'watch'
    assert post(c, '/api/prefs', {'level': 'alert', 'quiet': {'on': True, 'from': '23:00'}, 'events': {'scan': False}}).get_json()['level'] == 'alert'
    p = c.get('/api/prefs').get_json()
    assert p['quiet'] == {'on': True, 'from': '23:00', 'to': '07:00'} and p['events']['scan'] is False and p['events']['incident'] is True
    for bad in ({'level': 'calm'}, {'quiet': {'from': '25:00'}}, {'quiet': {'on': 'yes'}}, {'events': {'scan': 'no'}}):
        assert post(c, '/api/prefs', bad).status_code == 400, bad


GOOD = {'endpoint': 'https://fcm.googleapis.com/fcm/send/abc', 'keys': {'p256dh': 'B' * 87, 'auth': 'a' * 22}}


@pytest.mark.parametrize('ep,ok', [('https://fcm.googleapis.com/fcm/send/abc', True), ('https://updates.push.services.mozilla.com/wpush/v2/x', True), ('https://web.push.apple.com/Q1', True),
                                   ('https://wns2-par02p.notify.windows.com/w/?token=x', True),
                                   ('http://fcm.googleapis.com/x', False), ('https://127.0.0.1/x', False), ('https://localhost/x', False), ('https://169.254.169.254/latest/meta-data', False),
                                   ('https://192.168.0.1/admin', False), ('https://fcm.googleapis.com.evil.example/x', False), ('https://evilfcm.googleapis.com/x', False),
                                   ('https://evil.example/x', False), ('https://push.apple.com.evil.example/x', False), ('https://[::1]/x', False), ('ftp://fcm.googleapis.com/x', False)])
def test_push_endpoints_may_only_point_to_push_services(ep, ok):
    assert push_host_ok(ep) is ok, ep


def test_subscribe_and_unsubscribe(cli):
    c, fw, app = cli
    assert post(c, '/api/push/subscribe', {'subscription': GOOD}).get_json()['devices'] == 1
    assert post(c, '/api/push/subscribe', {'subscription': GOOD}).get_json()['devices'] == 1, 'the same device twice is one device'
    for bad in ({}, {'subscription': {}}, {'subscription': dict(GOOD, endpoint='https://169.254.169.254/x')}, {'subscription': dict(GOOD, keys={'p256dh': 'x', 'auth': 'y'})},
                {'subscription': dict(GOOD, endpoint='https://fcm.googleapis.com/' + 'a' * 800)}):
        assert post(c, '/api/push/subscribe', bad).status_code == 400, bad
    assert post(c, '/api/push/unsubscribe', {'endpoint': GOOD['endpoint']}).get_json()['devices'] == 0


def test_trusting_a_new_certificate_needs_the_password(cli):
    c, fw, app = cli
    c.get('/api/state')
    old = fw.fp
    fw.rotate_cert()
    app.extensions['sarah']['poller'].st_t = 0
    assert c.get('/api/state').get_json()['kind'] == 'pin'
    assert post(c, '/api/pin/trust', {'password': 'falsch'}).status_code == 401
    assert c.get('/api/state').get_json()['kind'] == 'pin', 'still refused'
    r = post(c, '/api/pin/trust', {'password': PW})
    assert r.status_code == 200 and old != fw.fp
    assert c.get('/api/state').get_json()['kind'] is None


def test_security_headers_and_caching(cli):
    c, fw, app = cli
    r = c.get('/api/state')
    assert r.headers['Cache-Control'] == 'no-store'
    r = c.get('/')
    csp = r.headers['Content-Security-Policy']
    assert "default-src 'self'" in csp and "script-src 'self'" in csp and 'unsafe-inline' not in csp.split('script-src')[1].split(';')[0] and "frame-ancestors 'none'" in csp
    assert r.headers['X-Content-Type-Options'] == 'nosniff' and r.headers['Referrer-Policy'] == 'no-referrer' and r.headers['Cache-Control'] == 'no-cache'
    assert c.get('/sw.js').headers['Service-Worker-Allowed'] == '/'
