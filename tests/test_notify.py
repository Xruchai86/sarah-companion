"""When S.A.R.A.H. pushes - and when she stays quiet."""
import copy, json, time
import pytest
from app.notify import decide, in_quiet
from app.store import DEFAULT_PREFS
from tests.fake_opn import base_status

NOW = int(time.mktime((2026, 10, 9, 14, 0, 0, 0, 0, -1)))
P = copy.deepcopy(DEFAULT_PREFS)


def st(**kw):
    s = base_status(NOW)
    s['last']['t'] = NOW - 300
    for k, v in kw.items():
        s[k] = v
    return s


def baseline(s=None, prefs=P):
    return decide({}, s or st(), {'items': []}, prefs, NOW)[1]


def kinds(notes):
    return [n['kind'] for n in notes]


def test_the_first_look_is_silent_even_if_things_are_going_on():
    s = st(open_incident=True)
    s['last'].update(level='alert', summary='Alarm')
    s['act']['proposals'] = [{'id': 'dns:doh', 'type': 'dns', 'descr': 'DoH sperren'}]
    s['act']['actions'] = [{'id': 5, 'who': 'S.A.R.A.H.', 'result': 'ok', 'type': 'isolate', 'ip': '1.2.3.4', 't': NOW}]
    notes, seen = decide({}, s, {'items': [{'id': 3, 'ok': True, 'urteil': 'gefaehrlich', 'name': 'x'}]}, P, NOW)
    assert notes == [] and seen['init'] and seen['last_t'] == s['last']['t'] and seen['action_id'] == 5 and seen['inv_id'] == 3


def test_a_calm_scan_stays_silent_a_worrying_one_speaks():
    seen = baseline()
    s = st(); s['last'].update(t=NOW + 600, level='calm', summary='Alles ruhig')
    assert decide(seen, s, None, P, NOW + 700)[0] == []
    s['last'].update(t=NOW + 1200, level='watch', summary='Ein Gerät umgeht die DNS-Sperre.', level_note='ein Gerät umgeht die DNS-Sperre trotz Durchsetzung')
    notes, seen2 = decide(seen, s, None, P, NOW + 1300)
    assert kinds(notes) == ['scan'] and notes[0]['title'] == 'S.A.R.A.H.: Beobachten' and 'DNS-Sperre' in notes[0]['body']
    assert decide(seen2, s, None, P, NOW + 1400)[0] == [], 'the same scan is never reported twice'


def test_alarm_and_the_minimum_level_setting():
    seen = baseline()
    s = st(); s['last'].update(t=NOW + 600, level='watch', summary='x')
    only_alarm = dict(copy.deepcopy(P), level='alert')
    assert decide(seen, s, None, only_alarm, NOW + 700)[0] == [], 'watch is below the chosen minimum'
    s['last'].update(t=NOW + 1200, level='alert', summary='Offener Vorfall')
    n = decide(seen, s, None, only_alarm, NOW + 1300)[0]
    assert n[0]['level'] == 'alert' and n[0]['title'] == 'S.A.R.A.H.: Alarm'


def test_a_failed_scan_never_pushes():
    seen = baseline()
    s = st(); s['last'].update(t=NOW + 600, ok=False, level='alert', summary='x')
    assert decide(seen, s, None, P, NOW + 700)[0] == []


def test_incident_opens_once():
    seen = baseline()
    s = st(open_incident=True)
    n, seen2 = decide(seen, s, None, P, NOW + 60)
    assert kinds(n) == ['incident'] and n[0]['level'] == 'alert'
    assert decide(seen2, s, None, P, NOW + 120)[0] == []
    seen3 = decide(seen2, st(open_incident=False), None, P, NOW + 180)[1]
    assert kinds(decide(seen3, st(open_incident=True), None, P, NOW + 240)[0]) == ['incident'], 'a new incident after a closed one speaks again'


def test_her_own_actions_speak_yours_do_not():
    seen = baseline()
    s = st()
    s['act']['actions'] = [{'id': 10, 'who': 'S.A.R.A.H.', 'result': 'ok', 'type': 'isolate', 'ip': '192.168.1.90', 'descr': 'kamera-hof', 't': NOW},
                           {'id': 11, 'who': 'du', 'result': 'ok', 'type': 'isolate', 'ip': '1.1.1.1', 't': NOW},
                           {'id': 12, 'who': 'S.A.R.A.H.', 'result': 'failed', 'type': 'dns', 'descr': 'DoH', 'error': 'HTTP 500', 't': NOW},
                           {'id': 13, 'who': 'S.A.R.A.H.', 'result': 'ok', 'type': 'dry', 'text': 'würde isolieren', 't': NOW},
                           {'id': 14, 'who': 'S.A.R.A.H.', 'result': 'ok', 'type': 'release', 't': NOW}]
    n, seen2 = decide(seen, s, None, P, NOW + 60)
    assert [x['title'] for x in n] == ['S.A.R.A.H. hat gehandelt: Gerät isoliert', 'Eingriff fehlgeschlagen']
    assert 'Veto' in n[0]['body'] and 'kamera-hof' in n[0]['body'] and 'HTTP 500' in n[1]['body']
    assert decide(seen2, s, None, P, NOW + 120)[0] == []


@pytest.mark.parametrize('verdict,level,push', [('harmlos', None, False), ('unklar', None, False), ('verdaechtig', 'watch', True), ('gefaehrlich', 'alert', True)])
def test_investigations(verdict, level, push):
    seen = baseline()
    inv = {'items': [{'id': 7, 'ok': True, 'urteil': verdict, 'name': 'kamera-hof', 'ip': '192.168.1.90', 'begruendung': 'Upload 32× über dem Grenzwert.'}]}
    n, seen2 = decide(seen, st(), inv, P, NOW + 60)
    assert bool(n) == push and (not push or (n[0]['level'] == level and 'kamera-hof' in n[0]['title']))
    assert decide(seen2, st(), inv, P, NOW + 120)[0] == []


def test_a_failed_investigation_is_silent():
    n = decide(baseline(), st(), {'items': [{'id': 8, 'ok': False, 'error': 'x'}]}, P, NOW + 60)[0]
    assert n == []


def test_proposals_wait_for_you():
    seen = baseline()
    s = st()
    s['act']['proposals'] = [{'id': 'shp:apply', 'type': 'shaper', 'descr': 'x'}, {'id': 'dns:doh', 'type': 'dns', 'descr': 'DoH-Resolver sperren', 'blocked_reason': 'erst 7 Stunden beobachtet'}]
    n, seen2 = decide(seen, s, None, P, NOW + 60)
    assert kinds(n) == ['proposal'] and 'Traffic-Shaping' in n[0]['body'] and 'DoH' not in n[0]['body'], 'a blocked proposal is not something to decide yet'
    assert decide(seen2, s, None, P, NOW + 120)[0] == []
    s['act']['proposals'] = []
    seen3 = decide(seen2, s, None, P, NOW + 180)[1]
    s['act']['proposals'] = [{'id': 'shp:apply', 'type': 'shaper'}]
    assert kinds(decide(seen3, s, None, P, NOW + 240)[0]) == ['proposal'], 'it comes back after it was gone'


def test_every_kind_can_be_switched_off():
    off = copy.deepcopy(P); off['events'] = {k: False for k in off['events']}
    seen = baseline(prefs=off)
    s = st(open_incident=True); s['last'].update(t=NOW + 600, level='alert', summary='x')
    s['act']['proposals'] = [{'id': 'shp:apply', 'type': 'shaper'}]
    s['act']['actions'] = [{'id': 20, 'who': 'S.A.R.A.H.', 'result': 'ok', 'type': 'isolate', 'ip': '1.2.3.4', 't': NOW}]
    assert decide(seen, s, {'items': [{'id': 9, 'ok': True, 'urteil': 'gefaehrlich', 'name': 'x'}]}, off, NOW + 700)[0] == []


def test_offline_watchdog():
    seen = baseline()
    n, seen = decide(seen, None, None, P, NOW + 60, 'Keine Verbindung zur Firewall', 'offline')
    assert n == [] and seen['offline_since'] == NOW + 60, 'a short outage is not worth a push'
    n, seen = decide(seen, None, None, P, NOW + 60 + 601, 'Keine Verbindung zur Firewall', 'offline')
    assert kinds(n) == ['offline'] and 'nicht erreichbar' in n[0]['title']
    assert decide(seen, None, None, P, NOW + 3000, 'x', 'offline')[0] == [], 'only once per outage'
    n, seen = decide(seen, st(), None, P, NOW + 3100)
    assert kinds(n) == ['offline'] and 'wieder erreichbar' in n[0]['title'] and 'offline_since' not in seen


def test_a_short_outage_that_ends_is_never_announced():
    seen = baseline()
    seen = decide(seen, None, None, P, NOW + 60, 'x', 'offline')[1]
    n, seen = decide(seen, st(), None, P, NOW + 200)
    assert n == []


def test_a_changed_certificate_alarms_at_once_and_only_once():
    seen = baseline()
    n, seen = decide(seen, None, None, P, NOW + 60, 'Zertifikat geändert', 'pin')
    assert kinds(n) == ['offline'] and n[0]['level'] == 'alert' and 'Zertifikat' in n[0]['title']
    assert decide(seen, None, None, P, NOW + 120, 'Zertifikat geändert', 'pin')[0] == []


def at(h, m=0, d=9):
    return int(time.mktime((2026, 10, d, h, m, 0, 0, 0, -1)))


def test_quiet_hours_hold_everything_but_an_alarm_and_send_one_digest_afterwards():
    q = copy.deepcopy(P); q['quiet'] = {'on': True, 'from': '22:00', 'to': '07:00'}
    assert in_quiet(q, at(23)) and in_quiet(q, at(3)) and not in_quiet(q, at(7)) and not in_quiet(q, at(21, 59)) and not in_quiet(P, at(23))
    seen = decide({}, st(), {'items': []}, q, at(21))[1]
    s = st(); s['last'].update(t=at(21) + 100, level='watch', summary='Eins')
    n, seen = decide(seen, s, None, q, at(23))
    assert n == [] and len(seen['held']) == 1
    s['last'].update(t=at(23) + 100, level='watch', summary='Zwei')
    s['act']['proposals'] = [{'id': 'shp:apply', 'type': 'shaper'}]
    n, seen = decide(seen, s, None, q, at(2, 0, 10))
    assert n == [] and len(seen['held']) == 3
    s['last'].update(t=at(2, 0, 10) + 100, level='alert', summary='Alarm!')
    n, seen = decide(seen, s, None, q, at(3, 0, 10))
    assert kinds(n) == ['scan'] and n[0]['level'] == 'alert', 'an alarm is not held'
    n, seen = decide(seen, s, None, q, at(7, 5, 10))
    assert kinds(n) == ['digest'] and 'Über Nacht: 3 Meldungen' in n[0]['title'] and '(×2)' in n[0]['body'] and seen['held'] == []
    assert decide(seen, s, None, q, at(7, 10, 10))[0] == [], 'the digest comes once'


def test_names_are_used_where_there_is_one_and_the_address_where_there_is_not():
    seen = baseline()
    s = st(); s['names'] = {'192.168.1.90': 'kamera-hof'}
    s['act']['proposals'] = [{'id': 'iso:192.168.1.90:1', 'type': 'isolate', 'ip': '192.168.1.90'}, {'id': 'pol:192.168.2.21', 'type': 'policy', 'ip': '192.168.2.21'}]
    s['act']['actions'] = [{'id': 30, 'who': 'S.A.R.A.H.', 'result': 'ok', 'type': 'isolate', 'ip': '192.168.1.90', 't': NOW}]
    n, _ = decide(seen, s, None, P, NOW + 60)
    text = ' | '.join(x['title'] + ' ' + x['body'] for x in n)
    assert 'kamera-hof (192.168.1.90) isolieren' in text and 'kamera-hof (192.168.1.90). Ein Veto' in text, text
    assert 'Richtlinie für 192.168.2.21' in text, 'no name known: the address'
    assert decide(seen, st(), None, P, NOW + 60)[0] == [] and decide(seen, dict(st(), names='kaputt'), None, P, NOW + 70)[0] == [], 'a broken names field does not break anything'
