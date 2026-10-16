"""Incidents in the Companion: the list comes from the firewall (cmd incidents), working on them (status, note, handover) goes through the
fixed command list with the firewall's own input rules; invalid input never reaches the firewall; a push about an incident opens the view."""
import base64, json
from tests.test_app import ctx, cli, login, post, H  # noqa: F401 - fixtures


def test_the_list_comes_from_the_firewall(cli):
    c, fw, app = cli
    r = c.get('/api/incidents').get_json()
    i = r['result']['incidents'][0]
    assert r['ok'] and i['ip'] == '192.168.1.90' and i['state'] == 'open' and ('POST', 'incidents', None) in fw.calls


def test_working_on_an_incident(cli):
    c, fw, app = cli
    until = fw.incidents['incidents'][0]['ack_until']
    r = post(c, '/api/incident/case', {'ip': '192.168.1.90', 'status': 'progress', 'until': until}).get_json()
    assert r['ok'] and r['result']['incidents'][0]['case']['status'] == 'progress'
    assert ('POST', 'icase', '192.168.1.90|progress:%d' % until) in fw.calls
    r = post(c, '/api/incident/note', {'ip': '192.168.1.90', 'text': 'Kollege fragen, ob RDP gewollt ist'}).get_json()
    sent = [x for x in fw.calls if x[1] == 'inote'][-1][2]
    assert r['ok'] and r['result']['incidents'][0]['case']['notes'][-1]['text'] == 'Kollege fragen, ob RDP gewollt ist'
    assert sent.startswith('192.168.1.90|') and '=' not in sent and ' ' not in sent, 'free text travels base64url, never as such'
    r = post(c, '/api/incident/handover', {'ip': '192.168.1.90'}).get_json()
    assert r['ok'] and r['result']['incidents'][0]['case']['sarah']['pending'] and ('POST', 'ihand', '192.168.1.90') in fw.calls
    r = post(c, '/api/incident/case', {'ip': '192.168.1.90', 'status': 'false', 'until': until}).get_json()
    assert r['result']['incidents'][0]['state'] == 'done'


def test_invalid_input_never_reaches_the_firewall(cli):
    c, fw, app = cli
    n = len(fw.calls)
    bad = [('/api/incident/case', {'ip': '192.168.1.90', 'status': 'deleted', 'until': 1}), ('/api/incident/case', {'ip': '192.168.1.90|done:1', 'status': 'done', 'until': 1}),
           ('/api/incident/case', {'ip': 'x', 'status': 'done', 'until': 1}), ('/api/incident/case', {'ip': '192.168.1.90', 'status': 'done', 'until': 'abc'}),
           ('/api/incident/note', {'ip': '192.168.1.90', 'text': ''}), ('/api/incident/note', {'ip': '192.168.1.90', 'text': 'x' * 1001}),
           ('/api/incident/note', {'ip': '1.2.3.4;ls', 'text': 'x'}), ('/api/incident/handover', {'ip': '192.168.1.90|x'})]
    for path, data in bad:
        r = post(c, path, data)
        assert r.status_code == 400, (path, data, r.get_json())
    assert len(fw.calls) == n


def test_needs_login_and_the_cross_site_header(ctx):
    app, c, fw = ctx
    assert c.get('/api/incidents').status_code == 401
    login(c)
    assert c.post('/api/incident/handover', data=json.dumps({'ip': '192.168.1.90'}), headers={'Content-Type': 'application/json'}).status_code == 403
    assert all(x[1] != 'ihand' for x in fw.calls)


def test_a_push_about_an_incident_opens_the_incidents():
    from app.notify import decide
    st = {'open_incident': True, 'last': {'t': 1, 'level': 'calm'}}
    notes, seen = decide({'init': True, 'incident': False}, st, {}, {'events': {}, 'level': 'watch', 'quiet': {'on': False}}, 100)
    inc = [n for n in notes if n['kind'] == 'incident']
    assert inc and inc[0]['tab'] == 'incidents'


def test_the_app_has_the_view():
    js = open(__file__.rsplit('/tests/', 1)[0] + '/app/static/app.js', encoding='utf-8').read()
    assert '["incidents", "Vorfälle"]' in js and '"/api/incident/case"' in js and '"/api/incident/handover"' in js
