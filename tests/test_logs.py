"""Monitoring over the Analyzer's logs (Panorama / FortiAnalyzer style) on a real DuckDB: the firewall log is parsed on arrival the way
OPNsense itself reads it (ref/core scripts/filter/read_log.py), 1.2.0 text lines are migrated; the four log types with filters (time, text,
fields, networks, negation, wildcard), paging, detail, summary, CSV without spreadsheet formulas; nothing from a request becomes SQL."""
import json, time
import pytest
from app.analyzer import Analyzer
from app.logs import Logs, BadQuery, parse_filterlog, where, safe_cell
from tests.test_app import ctx, cli, login, post, H  # noqa: F401 - fixtures

NOW = time.time()
ISO = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(NOW - 60))
FW_TCP4 = '81,,,02f4bab031b57d1e30553ce08e0ec131,igc0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.9,192.168.1.1,51000,22,0,S,1,,64240,,mss'
FW_UDP4 = '12,,,fae559338f65e11c53669fc3642c93c2,igc1,match,pass,out,4,0x0,,63,12345,0,none,17,udp,76,192.168.1.20,1.1.1.1,53001,53,56'
FW_TCP6 = '7,,,3f6a1e4c2b9d8a7e6f5c4b3a2d1e0f9a,igc0,match,block,in,6,0x00,0x00000,64,tcp,6,80,2001:db8::9,2001:db8::1,40000,443,0,S,1,,1024,,'
FW_ICMP = '5,,,02f4bab031b57d1e30553ce08e0ec131,igc0,match,pass,in,4,0x0,,64,1,0,none,1,icmp,84,198.51.100.4,192.168.1.1,request,1,1'


def ev(t, typ, src, dst, dport, **x):
    d = {"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000000+0000', time.gmtime(t)), "event_type": typ, "src_ip": src, "src_port": 50000, "dest_ip": dst, "dest_port": dport, "proto": "TCP"}
    d.update(x)
    return b"E " + json.dumps(d).encode()


@pytest.fixture
def L(tmp_path):
    a = Analyzer(str(tmp_path), {'ANALYZER_PORT': '0'}, default_allow='127.0.0.1')
    lines = [ev(NOW - 300, 'alert', '192.168.1.90', '185.66.66.66', 443, alert={"signature": "ET MALWARE Possible C2 Beacon", "severity": 1, "action": "allowed", "category": "A Network Trojan was detected", "signature_id": 2027000}),
             ev(NOW - 200, 'alert', '203.0.113.9', '192.168.1.20', 22, alert={"signature": "ET SCAN Nmap Scripting Engine", "severity": 2, "action": "blocked", "category": "Attempted Information Leak", "signature_id": 2009358}),
             ev(NOW - 100, 'tls', '192.168.1.20', '198.51.100.7', 443, tls={"sni": "www.example.org", "version": "TLS 1.3", "ja4": "t13d1516h2_8daaf6152771_02713d6af862"}),
             ev(NOW - 90, 'http', '192.168.1.21', '198.51.100.8', 80, http={"hostname": "pkg.example", "url": "/=cmd|calc", "http_user_agent": "=HYPERLINK(\"http://x\")"}),
             ev(NOW - 3 * 86400, 'alert', '192.168.1.50', '1.2.3.4', 80, alert={"signature": "alt", "severity": 3, "action": "allowed"})]
    lines += [("S %s filterlog %s" % (ISO, m)).encode() for m in (FW_TCP4, FW_UDP4, FW_TCP6, FW_ICMP)]
    lines += [("S %s audit /index.php: Successful login for user 'root' from: 192.168.1.10" % ISO).encode()]
    a.flush(lines)
    yield Logs(a)
    a.stop()


def test_filterlog_is_parsed_like_opnsense_reads_it():
    r = parse_filterlog(FW_TCP4)
    assert r == {'rid': '02f4bab031b57d1e30553ce08e0ec131', 'iface': 'igc0', 'action': 'block', 'dir': 'in', 'ipv': 4, 'proto': 'tcp', 'src': '203.0.113.9', 'sport': 51000,
                 'dst': '192.168.1.1', 'dport': 22, 'len': 60, 'rulenr': 81}
    u = parse_filterlog(FW_UDP4)
    assert (u['proto'], u['src'], u['sport'], u['dport'], u['action']) == ('udp', '192.168.1.20', 53001, 53, 'pass')
    s6 = parse_filterlog(FW_TCP6)
    assert (s6['ipv'], s6['src'], s6['dst'], s6['dport']) == (6, '2001:db8::9', '2001:db8::1', 443)
    i = parse_filterlog(FW_ICMP)
    assert i['proto'] == 'icmp' and i['sport'] is None and i['dport'] is None
    assert parse_filterlog('kein,firewall,log') is None and parse_filterlog('1,,,x,igc0,match,explode,in,4') is None


def test_the_four_log_types(L):
    th = L.search('threat', {})
    assert th['total'] == 2 and [r['sig'] for r in th['rows']] == ['ET SCAN Nmap Scripting Engine', 'ET MALWARE Possible C2 Beacon'], 'newest first, 24 h by default'
    assert th['rows'][1]['cat'] == 'A Network Trojan was detected' and th['rows'][1]['sid'] == 2027000
    ap = L.search('app', {})
    assert {r['host'] for r in ap['rows']} == {'www.example.org', 'pkg.example'} and any(r['version'] == 'TLS 1.3' and r['ja4'] for r in ap['rows'])
    tr = L.search('traffic', {})
    assert tr['total'] == 4 and {r['action'] for r in tr['rows']} == {'block', 'pass'}
    sy = L.search('system', {})
    assert sy['total'] == 1 and sy['rows'][0]['program'] == 'audit', 'filterlog lines are not in system'


def test_filters(L):
    assert L.search('threat', {'from': NOW - 7 * 86400})['total'] == 3
    assert L.search('threat', {'src': '192.168.1.90'})['total'] == 1
    assert L.search('threat', {'src': '!192.168.1.90'})['total'] == 1
    assert L.search('threat', {'sev': '1'})['total'] == 1
    assert L.search('threat', {'action': 'blocked'})['rows'][0]['sig'].startswith('ET SCAN')
    assert L.search('threat', {'q': 'trojan'})['total'] == 1, 'text search covers the category, case-insensitive'
    assert L.search('traffic', {'dst': '192.168.1.0/24'})['total'] == 2
    assert L.search('traffic', {'src': '2001:db8::/32'})['total'] == 1
    assert L.search('traffic', {'port': '22'})['total'] == 1 and L.search('traffic', {'port': '53'})['rows'][0]['proto'] == 'udp'
    assert L.search('app', {'host': '*.example.org'})['total'] == 1
    assert L.search('traffic', {'q': '100%'})['total'] == 0, 'a % in the text is a character, not a wildcard'


def test_nothing_from_the_request_becomes_sql(L):
    bad = [('threat', {'src': "1' OR '1'='1"}), ('threat', {'sev': '1 OR 1=1'}), ('threat', {'port': '22;DROP TABLE eve'}), ('nope', {}), ('threat', {'from': 'gestern'}),
           ('threat', {'from': NOW - 500 * 86400}), ('system', {'port': '22'}), ('system', {'sig': 'x'}), ('traffic', {'dst': '10.0.0.0/99'}), ('threat', {'q': 'x' * 201})]
    for kind, args in bad:
        with pytest.raises(BadQuery):
            L.search(kind, args)
    assert L.search('threat', {'from': NOW - 7 * 86400})['total'] == 3, 'still all there'
    sql, par = where('threat', {'src': '192.168.1.90', 'q': 'abc'}, NOW)
    assert '192.168.1.90' not in sql and 'abc' not in sql and '192.168.1.90' in par


def test_paging_detail_summary_csv(L):
    p1 = L.search('traffic', {'limit': 2})
    p2 = L.search('traffic', {'limit': 2, 'offset': 2})
    assert len(p1['rows']) == 2 and len(p2['rows']) == 2 and not {r['id'] for r in p1['rows']} & {r['id'] for r in p2['rows']}
    d = L.detail('threat', L.search('threat', {'sev': '1'})['rows'][0]['id'])
    assert json.loads(d['raw'])['alert']['signature_id'] == 2027000
    with pytest.raises(BadQuery):
        L.detail('threat', L.search('app', {})['rows'][0]['id'] + 999)
    s = L.summary('threat', {'from': NOW - 7 * 86400})
    assert sum(h['n'] for h in s['hist']) == 3 and s['top']['src'][0]['n'] == 1 and {x['v'] for x in s['top']['action']} == {'allowed', 'blocked'}
    assert {x['v'] for x in L.summary('traffic', {})['top']['dport']} == {'22', '53', '443'}
    c = L.csv('app', {})
    lines = c.lstrip('﻿').splitlines()
    assert lines[0].startswith('t;type;src') and len(lines) == 3 and "'=HYPERLINK" in c, 'a cell (here a user agent) that starts like a formula is neutralised'
    assert safe_cell('=1+1') == "'=1+1" and safe_cell('-2') == "'-2" and safe_cell('ok') == 'ok'


def test_lines_of_1_2_0_are_migrated(tmp_path):
    a = Analyzer(str(tmp_path), {'ANALYZER_PORT': '0'})
    with a.dblock:
        a.con.execute("INSERT INTO sys VALUES (?, 'filterlog', ?), (?, 'audit', 'login')", [NOW - 50, FW_TCP4, NOW - 40])
    a.stop()
    b = Analyzer(str(tmp_path), {'ANALYZER_PORT': '0'})
    L = Logs(b)
    assert L.search('traffic', {})['total'] == 1 and L.search('system', {})['total'] == 1


def test_applications_per_device_come_from_the_firewall(cli):
    c, fw, app = cli
    r = c.get('/api/apps').get_json()
    assert r['ok'] and r['result']['source'] == 'zenarmor' and r['result']['devices'][0]['ip'] == '192.168.1.20' and ('POST', 'apps', None) in fw.calls
    r = c.get('/api/apps?device=0A:00:27:00:00:04').get_json()
    assert r['result']['devices'][0]['zapps'][0]['name'] == 'Netflix' and ('POST', 'appdev', '0a:00:27:00:00:04') in fw.calls
    n = len(fw.calls)
    assert c.get('/api/apps?device=x;rm').status_code == 400 and len(fw.calls) == n, 'an invalid device never reaches the firewall'
    assert app.test_client().get('/api/apps').status_code == 401


def test_the_api(cli):
    c, fw, app = cli
    a = app.extensions['sarah']['analyzer']
    a.flush([ev(NOW - 30, 'alert', '192.168.1.90', '185.66.66.66', 443, alert={"signature": "X", "severity": 1, "action": "allowed"}), ("S %s filterlog %s" % (ISO, FW_TCP4)).encode()])
    r = c.get('/api/logs/threat?sev=1').get_json()
    assert r['total'] == 1 and r['rows'][0]['sig'] == 'X'
    assert c.get('/api/logs/threat?src=1%27%20OR%201=1').status_code == 400
    assert c.get('/api/logs/traffic/summary').get_json()['top']['dport'][0]['v'] == '22'
    assert c.get('/api/logs/counts').get_json() == {'threat': 1, 'app': 0, 'traffic': 1, 'system': 0}
    r = c.get('/api/logs/threat/csv')
    assert r.status_code == 200 and 'attachment' in r.headers['Content-Disposition'] and r.mimetype == 'text/csv'
    rid = c.get('/api/logs/threat').get_json()['rows'][0]['id']
    assert json.loads(c.get('/api/logs/threat/entry/%d' % rid).get_json()['raw'])['alert']['signature'] == 'X'
    fw.rulemap = {'02f4bab031b57d1e30553ce08e0ec131': 'Default deny rule'}
    assert c.get('/api/logs/rules').get_json() == {'02f4bab031b57d1e30553ce08e0ec131': 'Default deny rule'}
    c2 = app.test_client()
    assert c2.get('/api/logs/threat').status_code == 401
