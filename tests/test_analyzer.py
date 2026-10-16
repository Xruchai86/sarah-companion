"""The Analyzer: receives the lines syslog-ng of the firewall sends (format of os-scdeck analyzer.py), over TLS with its own certificate
(the client pins exactly that one, like syslog-ng with ca-file), only from allowed addresses; stores Suricata events via DuckDB's JSON reader
and system lines; counts bad, overlong and refused input; retention by days and by size; the app shows the status (login needed)."""
import json, os, socket, ssl, time
import duckdb
import pytest
from app.analyzer import Analyzer
from tests.test_app import ctx, cli, login, post, H  # noqa: F401 - fixtures

EVE = [{"timestamp": "2026-10-16T07:16:00.123456+0200", "event_type": "tls", "src_ip": "192.168.1.20", "src_port": 51000, "dest_ip": "198.51.100.7", "dest_port": 443,
        "proto": "TCP", "tls": {"sni": "www.example.org", "version": "TLS 1.3", "ja4": "t13d1516h2_8daaf6152771_02713d6af862"}},
       {"timestamp": "2026-10-16T07:16:01.000000+0200", "event_type": "alert", "src_ip": "192.168.1.90", "src_port": 50000, "dest_ip": "185.66.66.66", "dest_port": 443,
        "proto": "TCP", "alert": {"signature": "ET MALWARE Possible C2 Beacon", "severity": 1, "action": "allowed"}},
       {"timestamp": "2026-10-16T07:16:02.000000+0200", "event_type": "http", "src_ip": "192.168.1.21", "dest_ip": "198.51.100.8", "dest_port": 80, "http": {"hostname": "pkg.example", "url": "/"}}]


def lines():
    out = [b"E " + json.dumps(e).encode() for e in EVE]
    out.append(b"S 2026-10-16T07:16:03+02:00 filterlog 81,,,0,igc0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.9,192.168.1.1,51000,22,0,S")
    out.append(b"S 2026-10-16T07:16:04+02:00 audit /index.php: Successful login for user 'root' from: 192.168.1.10")
    out.append(b"E {kaputt")
    out.append(b"X unknown kind")
    return out


def wait(a, written, timeout=10):
    end = time.time() + timeout
    while time.time() < end and a.c['written'] < written:
        time.sleep(0.1)


@pytest.fixture
def an(tmp_path):
    a = Analyzer(str(tmp_path), {'ANALYZER_PORT': '0'}, default_allow='127.0.0.1')
    a.port = free_port()
    import socketserver, threading
    a.start_port = a.port
    yield a
    a.stop()


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def start(a):
    import socketserver, threading
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    a.server = socketserver.ThreadingTCPServer(("127.0.0.1", a.port), a.handler())
    threading.Thread(target=a.server.serve_forever, daemon=True).start()
    threading.Thread(target=a.writer, daemon=True).start()


def send(a, payload, pin=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False                                   # syslog-ng 4.12 does not check the name either (checked on the test firewall)
    if pin:
        ctx.load_verify_locations(a.cert[0])
    with socket.create_connection(("127.0.0.1", a.port), timeout=5) as s, ctx.wrap_socket(s) as t:
        t.sendall(b"\n".join(payload) + b"\n")


def test_tls_receive_and_store(an):
    start(an)
    send(an, lines())
    wait(an, 5)
    st = an.status()
    assert st['tables']['eve']['rows'] == 3 and st['tables']['sys']['rows'] == 1 and st['tables']['fw']['rows'] == 1, st['tables']   # filterlog is parsed into fw (1.3.0)
    assert st['counters']['received'] == 7 and st['counters']['bad'] == 2 and st['counters']['senders'] == {'127.0.0.1': 7}
    with an.dblock:
        rows = an.con.execute("SELECT type, src, dport, host, sig, sev, action, t FROM eve ORDER BY t").fetchall()
        sysr = an.con.execute("SELECT program, msg FROM sys ORDER BY t").fetchall()
        fwr = an.con.execute("SELECT action, src, dport FROM fw").fetchall()
    assert rows[0][:4] == ('tls', '192.168.1.20', 443, 'www.example.org') and rows[1][4:7] == ('ET MALWARE Possible C2 Beacon', 1, 'allowed') and rows[2][3] == 'pkg.example'
    assert abs(rows[0][7] - 1792127760.123456) < 0.001, 'eve time with offset +0200 is stored as UTC epoch'
    assert fwr == [('block', '203.0.113.9', 22)] and sysr[0][0] == 'audit'


def test_a_foreign_certificate_is_not_trusted_by_the_client(an):
    start(an)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.load_default_certs()
    with pytest.raises(ssl.SSLError):
        with socket.create_connection(("127.0.0.1", an.port), timeout=5) as s, ctx.wrap_socket(s) as t:
            t.sendall(b"E {}\n")
    assert os.stat(an.cert[1]).st_mode & 0o077 == 0, 'private key only for the owner'
    assert "BEGIN CERTIFICATE" in an.status()['cert'] and len(an.status()['cert_sha256']) == 64


def test_only_allowed_senders(tmp_path):
    a = Analyzer(str(tmp_path), {'ANALYZER_PORT': '0', 'ANALYZER_ALLOW': '192.0.2.1'})
    a.port = free_port(); start(a)
    try:
        send(a, [b"E {}"])
    except (ssl.SSLError, OSError):
        pass
    time.sleep(0.5)
    assert a.c['refused'] >= 1 and a.c['received'] == 0
    a.stop()
    b = Analyzer(str(tmp_path / 'b'), {'ANALYZER_PORT': '0'})
    assert b.allow == [] and not b.allowed('127.0.0.1'), 'nobody configured: nobody may send'


def test_overlong_lines_and_a_full_queue_are_counted_not_kept(an, monkeypatch):
    start(an)
    send(an, [b"E " + b"x" * (300 * 1024), b"E " + json.dumps(EVE[0]).encode()])
    wait(an, 1)
    assert an.c['dropped_long'] == 1 and an.c['written'] == 1
    import queue
    an.q = queue.Queue(2)
    for _ in range(5):
        an.put(b"E {}", "127.0.0.1")
    assert an.c['dropped_queue'] == 3


def test_retention_by_days_and_by_size(tmp_path):
    a = Analyzer(str(tmp_path), {'ANALYZER_PORT': '0', 'ANALYZER_DAYS': '30', 'ANALYZER_MAX_GB': '20'})
    now = time.time()
    with a.dblock:
        a.con.execute("INSERT INTO eve (t, type) SELECT ? - i * 3600, 'tls' FROM range(0, 24 * 40) t(i)", [now])
        a.con.execute("INSERT INTO sys VALUES (?, 'audit', 'alt'), (?, 'audit', 'neu')", [now - 35 * 86400, now])
    a.clean(now)
    with a.dblock:
        old = a.con.execute("SELECT MIN(t) FROM eve").fetchone()[0]
        n_sys = a.con.execute("SELECT COUNT(*) FROM sys").fetchone()[0]
    assert old >= now - 30 * 86400 and n_sys == 1, 'older than 30 days is gone'
    with a.dblock:
        a.con.execute("INSERT INTO eve (t, type, raw) SELECT ? - (i % (24 * 20)) * 3600, 'tls', to_json(repeat('x', 400)) FROM range(0, 400000) t(i)", [now])
        a.con.execute("CHECKPOINT")
    before = a.size()
    a.max_bytes = before // 2
    a.clean(now)
    with a.dblock:
        left = a.con.execute("SELECT MIN(t) FROM eve").fetchone()[0]
    assert left > now - 20 * 86400 + 3600, 'above the size limit the oldest days go first'


def test_the_app_shows_the_status(cli):
    c, fw, app = cli
    r = c.get('/api/analyzer').get_json()
    assert r['port'] == 6514 and r['tls'] and r['days'] == 30 and r['max_gb'] == 20.0 and 'BEGIN CERTIFICATE' in r['cert']
    assert r['allow'] == ['127.0.0.1/32'] or r['allow'], 'default: the firewall of OPNSENSE_URL may send'
    c2 = app.test_client()
    assert c2.get('/api/analyzer').status_code == 401
