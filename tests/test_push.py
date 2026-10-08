"""Delivery: a real web push (VAPID, aes128gcm) to a stand-in push service, decrypted the way a browser does it; ntfy; the poll clock end to end."""
import base64, json, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import http_ece
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from app.notify import Pusher, Poller, note
from app.opn import Opn


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


class PushService:
    """what Google/Mozilla/Apple run, reduced to: remember the request, answer with a status"""
    def __init__(self):
        self.got, self.status = [], 201
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get('Content-Length', 0))
                outer.got.append((self.path, dict(self.headers), self.rfile.read(n)))
                self.send_response(outer.status if not self.path.startswith('/gone') else 410)
                self.send_header('Content-Length', '0')
                self.end_headers()
        self.httpd = HTTPServer(('127.0.0.1', 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def device(self, store, path='/push/a'):
        priv = ec.generate_private_key(ec.SECP256R1())
        auth = os.urandom(16)
        pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        store.add_sub({'endpoint': 'http://127.0.0.1:%d%s' % (self.port, path), 'keys': {'p256dh': b64(pub), 'auth': b64(auth)}}, 'test')
        return priv, auth

    def stop(self):
        self.httpd.shutdown()


@pytest.fixture
def svc():
    s = PushService()
    yield s
    s.stop()


def test_the_message_arrives_encrypted_and_signed(svc, store):
    priv, auth = svc.device(store)
    p = Pusher(store, store.dir, 'mailto:test@example.com')
    r = p.send(note('scan', 'alert', 'S.A.R.A.H.: Alarm', 'Offener Vorfall bei kamera-hof', 'core', 'scan'))
    assert r['sent'] == 1 and r['errors'] == []
    path, headers, body = svc.got[0]
    clear = json.loads(http_ece.decrypt(body, private_key=priv, auth_secret=auth, version='aes128gcm'))
    assert clear['title'] == 'S.A.R.A.H.: Alarm' and clear['body'].startswith('Offener Vorfall') and clear['tag'] == 'scan' and clear['tab'] == 'core' and clear['level'] == 'alert'
    h = {k.lower(): v for k, v in headers.items()}
    assert h['content-encoding'] == 'aes128gcm' and h['urgency'] == 'high' and int(h['ttl']) > 0
    assert h['authorization'].startswith('vapid t=') and ('k=' + p.public_key()) in h['authorization'], 'signed with OUR key: the push service can tell it is us'


def test_a_normal_message_is_not_urgent(svc, store):
    svc.device(store)
    Pusher(store, store.dir, 'mailto:t@example.com').send(note('proposal', 'watch', 'x', 'y'))
    assert {k.lower(): v for k, v in svc.got[0][1].items()}['urgency'] == 'normal'


def test_the_key_survives_a_restart(store):
    a = Pusher(store, store.dir, 'mailto:t@example.com')
    b = Pusher(store, store.dir, 'mailto:t@example.com')
    assert a.public_key() == b.public_key() and len(a.public_key()) == 87
    assert oct(os.stat(os.path.join(store.dir, 'vapid_private.pem')).st_mode & 0o777) == '0o600'


def test_a_device_that_is_gone_is_forgotten_and_does_not_block_the_others(svc, store):
    svc.device(store, '/gone/1')
    priv, auth = svc.device(store, '/push/ok')
    r = Pusher(store, store.dir, 'mailto:t@example.com').send(note('scan', 'watch', 'a', 'b'))
    assert r['sent'] == 1 and r['removed'] == 1 and len(store.subs()) == 1 and store.subs()[0]['sub']['endpoint'].endswith('/push/ok')


def test_a_push_service_error_keeps_the_device(svc, store):
    svc.device(store); svc.status = 500
    r = Pusher(store, store.dir, 'mailto:t@example.com').send(note('scan', 'watch', 'a', 'b'))
    assert r['sent'] == 0 and r['removed'] == 0 and r['errors'] == ['HTTP 500'] and len(store.subs()) == 1


def test_ntfy_gets_a_utf8_json_message(store):
    got = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            got.append((dict(self.headers), json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
            self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
    srv = HTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        p = Pusher(store, store.dir, 'mailto:t@example.com', 'http://127.0.0.1:%d' % srv.server_address[1], 'sarah', 'tk_secret')
        r = p.send(note('scan', 'alert', 'S.A.R.A.H.: Alarm', 'Gerät „Küche“ umgeht die Sperre'))
        h, body = got[0]
        assert r['ntfy'] == 200 and body['topic'] == 'sarah' and body['priority'] == 4 and 'Küche' in body['message'] and h['Authorization'] == 'Bearer tk_secret'
    finally:
        srv.shutdown()


class Pushes:
    def __init__(self): self.sent = []
    def send(self, n): self.sent.append(n); return {}
    def public_key(self): return 'k'


def test_the_poll_clock_end_to_end(fw, store):
    t = [1_800_000_000]
    push = Pushes()
    poller = Poller(Opn(fw.url, fw.key, fw.secret, store, timeout=5), store, push, clock=lambda: t[0])
    assert poller.tick() == [] and push.sent == [], 'first look: baseline only'
    fw.status['last'].update(t=t[0] + 100, level='watch', summary='Ein Gerät umgeht die Sperre.')
    t[0] += 120
    assert [n['kind'] for n in poller.tick()] == ['scan'] and len(push.sent) == 1
    assert poller.tick() == [], 'nothing new, nothing sent'
    # a restart: a new poller with the same data folder must not report it again
    poller2 = Poller(Opn(fw.url, fw.key, fw.secret, store, timeout=5), store, push, clock=lambda: t[0])
    t[0] += 60
    assert poller2.tick() == [] and len(push.sent) == 1
    # the firewall goes away: after 10 minutes one push, and one when it is back
    fw.mode = 'drop'
    t[0] += 60; assert poller2.tick() == [] and poller2.health['ok'] is False and poller2.health['kind'] == 'offline'
    t[0] += 700; assert [n['kind'] for n in poller2.tick()] == ['offline']
    t[0] += 60; assert poller2.tick() == []
    fw.mode = None
    t[0] += 60; n = poller2.tick(); assert [x['title'] for x in n] == ['Firewall wieder erreichbar'] and poller2.health['ok'] is True


def test_a_changed_certificate_is_pushed_at_once(fw, store):
    t = [1_800_000_000]
    push = Pushes()
    poller = Poller(Opn(fw.url, fw.key, fw.secret, store, timeout=5), store, push, clock=lambda: t[0])
    poller.tick()
    fw.rotate_cert()
    t[0] += 60
    n = poller.tick()
    assert [x['level'] for x in n] == ['alert'] and 'Zertifikat' in n[0]['title'] and poller.health['kind'] == 'pin'
