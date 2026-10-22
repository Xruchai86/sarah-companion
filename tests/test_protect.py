"""Protection (DECK › Schutzprofile) in the Companion: the view and the previews come from /api/scdeck/stats/protect (read only), applying and
taking back go through S.A.R.A.H.'s fixed commands (do prf:/sup:/dvt:, release), the two settings through deckset. Every input is checked
here with the firewall's own rules before anything is sent; the firewall decides (mode, memory, Divert state)."""
import json
import pytest
from app.main import create_app
from app.opn import Opn, OpnError, check_command

PW = 'ein-langes-passwort'
H = {'X-Requested-With': 'sarah', 'Content-Type': 'application/json'}


@pytest.fixture
def cli(fw, tmp_path):
    env = {'UI_PASSWORD': PW, 'OPNSENSE_URL': fw.url, 'OPNSENSE_KEY': fw.key, 'OPNSENSE_SECRET': fw.secret, 'DATA_DIR': str(tmp_path / 'data'), 'ANALYZER_PORT': '0'}
    app = create_app(env, start_poller=False)
    c = app.test_client()
    assert c.post('/api/login', json={'password': PW}, headers={'X-Requested-With': 'sarah'}).status_code == 200
    return c, fw


def post(c, path, data):
    return c.post(path, data=json.dumps(data), headers=H)


def test_nothing_without_login(fw, tmp_path):
    env = {'UI_PASSWORD': PW, 'OPNSENSE_URL': fw.url, 'OPNSENSE_KEY': fw.key, 'OPNSENSE_SECRET': fw.secret, 'DATA_DIR': str(tmp_path / 'd'), 'ANALYZER_PORT': '0'}
    c = create_app(env, start_poller=False).test_client()
    for path in ('/api/protect', '/api/protect/plan?zone=lan&level=basis', '/api/protect/ids?level=basis'):
        assert c.get(path).status_code == 401, path
    assert c.post('/api/protect/set', json={'key': 'dvtzen', 'value': 'on'}, headers={'X-Requested-With': 'sarah'}).status_code == 401
    assert fw.calls == []


def test_the_overview_is_the_firewalls(cli):
    c, fw = cli
    r = c.get('/api/protect')
    assert r.status_code == 200
    d = r.get_json()['result']
    assert [z['key'] for z in d['zones']] == ['lan', 'opt1'] and d['divert']['state'] == 'active' and d['idspol']['level'] == 'standard'
    assert ('GET', 'protect', '') in fw.calls


def test_previews_carry_only_checked_values(cli):
    c, fw = cli
    r = c.get('/api/protect/plan?zone=lan&level=streng')
    assert r.status_code == 200 and r.get_json()['result']['changes'][0]['kind'] == 'dnsbl_level'
    assert ('GET', 'protect', 'zone=lan&level=streng') in fw.calls
    r = c.get('/api/protect/plan?zone=opt1&level=streng').get_json()['result']
    assert r['blocked'] and r['memory']['state'] == 'block', 'the memory check of the firewall reaches the app'
    assert c.get('/api/protect/ids?level=basis').get_json()['result']['changes']
    n = len(fw.calls)
    for bad in ('/api/protect/plan?zone=LAN&level=basis', '/api/protect/plan?zone=lan%26ids%3Dbasis&level=basis', '/api/protect/plan?zone=lan&level=hart',
                '/api/protect/plan?zone=lan', '/api/protect/ids?level=', '/api/protect/ids?level=streng%26zone=lan'):
        r = c.get(bad)
        assert r.status_code == 400 and r.get_json()['kind'] == 'input', bad
    assert len(fw.calls) == n, 'nothing invalid reaches the firewall'


def test_apply_and_take_back_a_profile(cli):
    c, fw = cli
    r = post(c, '/api/do', {'id': 'prf:lan:streng'})
    assert r.status_code == 200, r.get_json()
    ap = c.get('/api/protect').get_json()['result']['applied']['lan']
    new = [a for a in ap if a['level'] == 'streng'][0]
    assert ('POST', 'do', 'prf:lan:streng') in fw.calls
    assert post(c, '/api/release', {'id': str(new['id'])}).status_code == 200
    assert all(a['level'] != 'streng' for a in c.get('/api/protect').get_json()['result']['applied'].get('lan', []))


def test_the_firewall_has_the_last_word(cli):
    c, fw = cli
    r = post(c, '/api/do', {'id': 'prf:opt1:streng'})
    assert r.status_code == 400 and 'Speicher' in r.get_json()['error'], 'too little memory: refused by the firewall, not by the app'
    fw.status['config']['mode'] = 'observe'
    r = post(c, '/api/do', {'id': 'sup:streng'})
    assert r.status_code == 400 and 'Modus' in r.get_json()['error']


def test_policies_and_divert_commands(cli):
    c, fw = cli
    assert post(c, '/api/do', {'id': 'sup:streng'}).status_code == 200
    v = c.get('/api/protect').get_json()['result']['idspol']
    assert v['level'] == 'streng' and v['entry']
    assert post(c, '/api/do', {'id': 'dvt:now'}).status_code == 400, 'Divert does not wait: the firewall says so'
    assert post(c, '/api/protect/set', {'key': 'dvtzen', 'value': 'on'}).status_code == 200
    assert ('POST', 'deckset', 'on', 'dvtzen') in fw.calls
    assert post(c, '/api/do', {'id': 'dvt:zen'}).status_code == 200
    d = c.get('/api/protect').get_json()['result']['divert']
    assert d['zen_layer'] and all(r['divert'] for r in d['in'] if r['zen'])
    for bad in ('dvt:off', 'sup:hart', 'prf:LAN:basis', 'prf:lan:basis;x'):
        assert post(c, '/api/do', {'id': bad}).status_code == 400, bad


def test_only_the_two_settings_can_be_switched(cli):
    c, fw = cli
    assert post(c, '/api/protect/set', {'key': 'pskip', 'value': 'opt2,opt1'}).status_code == 200
    assert [x['key'] for x in c.get('/api/protect').get_json()['result']['choose'] if x['skip']] == ['opt1', 'opt2']
    assert post(c, '/api/protect/set', {'key': 'pskip', 'value': 'none'}).status_code == 200
    n = len(fw.calls)
    for k, v in (('lang', 'en'), ('dhcp', 'kea'), ('dvtzen', 'yes'), ('pskip', 'opt2;reboot'), ('pskip', 'OPT2'), ('pskip', ''), ('', 'on')):
        r = post(c, '/api/protect/set', {'key': k, 'value': v})
        assert r.status_code == 400 and r.get_json()['kind'] == 'input', (k, v)
    assert len(fw.calls) == n


def test_an_old_plugin_says_what_to_do(cli):
    c, fw = cli
    fw.protect_mode = '403'
    r = c.get('/api/protect')
    assert r.status_code == 502 and r.get_json()['kind'] == 'auth' and '0.79' in r.get_json()['error']
    assert c.get('/api/state').get_json()['kind'] is None, "S.A.R.A.H.'s own interface keeps working"


def test_check_command_mirrors_the_firewall():
    for ok in ('prf:lan:basis', 'prf:opt12:streng', 'sup:standard', 'dvt:apply', 'dvt:now', 'dvt:zen'):
        assert check_command('do', ok) == ok
    for bad in ('prf:lan', 'prf:lan:standard:x', 'sup:', 'dvt:', 'dvt:apply2'):
        with pytest.raises(OpnError):
            check_command('do', bad)
    assert check_command('deckset', 'on', 'dvtzen') == 'on'
    assert check_command('deckset', 'opt4,opt5', 'dvtskip') == 'opt4,opt5'      # 0.81: Zenarmor zones left out of the second layer
    with pytest.raises(OpnError):
        check_command('deckset', 'opt4;rm', 'dvtskip')
    with pytest.raises(OpnError):
        check_command('deckset', 'on', 'lang')


def test_protect_refuses_bad_input_without_a_request(fw, store):
    o = Opn(fw.url, fw.key, fw.secret, store, timeout=5)
    for kw in ({'zone': 'lan', 'level': 'x'}, {'zone': '../x', 'level': 'basis'}, {'ids': 'x'}):
        with pytest.raises(OpnError):
            o.protect(**kw)
    assert fw.calls == []
