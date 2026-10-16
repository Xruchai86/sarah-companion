"""Analyzer mode, the Companion's half: the Feeder picks tls/http and alerts out of each stored batch, sums up records of inside devices only
once the firewall named its own addresses, keeps its buffers bounded, delivers through the fixed command `feed` with the firewall's input
rules, counts failures, and delivers nothing while no lines arrive. The firewall's half (sarah.py feed) is tested in the DECK's t_feed."""
import json, time
import pytest
from app.analyzer import Analyzer
from app import feeder as F
from app.opn import check_command, OpnError
from tests.test_app import ctx, cli  # noqa: F401 - fixtures

NOW = time.time()


def ev(i, src='192.168.1.20', **x):
    d = {"timestamp": "2026-10-16T07:16:%02d.000000+0000" % (i % 60), "event_type": "tls", "src_ip": src, "src_port": 50000 + i, "dest_ip": "198.51.100.7", "dest_port": 443,
         "proto": "TCP", "tls": {"sni": "www.example.org", "version": "TLS 1.3", "ja4": "t13d_x"}}
    d.update(x)
    return b"E " + json.dumps(d).encode()


class Fw:
    def __init__(self, answer=None, fail=None):
        self.sent, self.answer, self.fail = [], answer or {'ok': True, 'own': ['10.0.3.15']}, fail

    def command(self, cmd, value=''):
        check_command(cmd, value)
        if self.fail:
            raise OpnError(self.fail)
        self.sent.append(json.loads(value))
        return self.answer


@pytest.fixture
def an(tmp_path):
    a = Analyzer(str(tmp_path), {'ANALYZER_PORT': '0'}, default_allow='127.0.0.1')
    yield a
    a.stop()


def test_pick_and_sum_up(an):
    an.flush([ev(i) for i in range(30)] + [ev(99, src='10.0.3.15'), ev(98, src='10.0.3.15'),
              b'E ' + json.dumps({"timestamp": "2026-10-16T07:16:00.000000+0000", "event_type": "alert", "src_ip": "192.168.1.90", "dest_ip": "1.2.3.4",
                                  "alert": {"signature": "X", "signature_id": 1, "severity": 1, "action": "allowed", "category": "c"}}).encode(),
              b'E ' + json.dumps({"event_type": "flow", "src_ip": "192.168.1.20"}).encode()])
    fw = Fw()
    assert an.feeder.deliver(fw, True)
    p = fw.sent[0]
    assert len(p['tls_http']) == 32 and len(p['alerts']) == 1 and p['tls_any'], 'first delivery: own addresses unknown, nothing summed up; flow events are not sent'
    assert an.feeder.own == {'10.0.3.15'}
    an.flush([ev(i) for i in range(30)] + [ev(99, src='10.0.3.15'), ev(98, src='10.0.3.15')])
    an.feeder.deliver(fw, True)
    p = fw.sent[1]
    dev = [r for r in p['tls_http'] if r['src_ip'] == '192.168.1.20']
    own = [r for r in p['tls_http'] if r['src_ip'] == '10.0.3.15']
    assert len(dev) == 1 and dev[0]['_n'] == 30 and dev[0]['tls'] == {'sni': 'www.example.org', 'version': 'TLS 1.3', 'ja4': 't13d_x'}
    assert len(own) == 2 and {r['src_port'] for r in own} == {50099, 50098}, 'the firewall\'s own address stays per connection (NAT mapping)'
    assert an.status()['feed']['delivered'] == 2 and an.status()['feed']['records'] == 33 + 3


def test_no_lines_no_delivery_and_failures_are_counted(an):
    an.flush([ev(1)])
    fw = Fw()
    assert not an.feeder.deliver(fw, False) and fw.sent == []
    an.flush([ev(2)])
    an.feeder.deliver(fw, True)
    assert len(fw.sent[0]['tls_http']) == 1, 'what came in while nothing arrived from the firewall was not piled up'
    bad = Fw(fail='Keine Verbindung zur Firewall')
    an.flush([ev(3)])
    assert not an.feeder.deliver(bad, True)
    assert an.feeder.c['failed'] == 1 and 'Keine Verbindung' in an.feeder.c['error']
    rej = Fw(answer={'error': 'invalid feed'})
    an.flush([ev(4)])
    assert not an.feeder.deliver(rej, True) and an.feeder.c['failed'] == 2


def test_buffers_are_bounded(monkeypatch):
    f = F.Feeder()
    f.th = __import__('collections').deque(maxlen=3)
    with f.lock:
        pass
    for i in range(5):
        if len(f.th) == f.th.maxlen:
            f.c['dropped'] += 1
        f.th.append(('t', 'tls', '192.168.1.%d' % i, 1, 'd', 443, 'TCP', 's%d' % i, None, None, None, None))
    assert f.c['dropped'] == 2 and len(f.payload()['tls_http']) == 3
    monkeypatch.setattr(F, 'MAX_TH', 2)
    for i in range(3):
        f.th.append(('t', 'tls', '192.168.1.%d' % i, 1, 'd', 443, 'TCP', 's%d' % i, None, None, None, None))
    assert len(f.payload()['tls_http']) == 2 and f.c['dropped'] == 3


def test_the_command_has_a_size_limit():
    with pytest.raises(OpnError):
        check_command('feed', 'x' * (8 * 1024 * 1024 + 1))
    assert check_command('feed', '{}') == '{}'
