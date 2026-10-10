"""A stand-in for the firewall: HTTPS (self-signed, exchangeable), HTTP Basic, and /api/scdeck/stats/sarah with the same input rules as
StatsController::sarahArgs and answers shaped like the real ones (taken from sarah.status(), sarahact.view(), invest.listing(), the tasks)."""
import base64
import copy
import datetime
import hashlib
import json
import re
import ssl
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ACTION_ID = re.compile(r'(iso:[0-9a-fA-F.:]{3,45}:\d{1,12}|rul:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|dns:(rdr|doh|dot)|shp:apply|ids:(alert|off):\d{1,10}|ids:sets|tsk:[0-9]{1,6}|cat:[a-z0-9-]{1,40}|pol:(([0-9a-f]{2}:){5}[0-9a-f]{2}|[0-9a-fA-F.:]{3,45}))')


def make_cert(cn='opnsense.test'):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName('localhost')]), False).sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cf, kf = d + '/c.pem', d + '/k.pem'
    open(cf, 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
    open(kf, 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cf, kf, hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def base_status(now):
    return {'now': now, 'enabled': True, 'state': 'calm', 'level': 'calm', 'open_incident': False, 'running': False,
            'config': {'provider': 'ollama', 'url': 'http://192.168.0.45:11434', 'model': 'gpt-oss:20b', 'mode': 'auto', 'interval': 60, 'cap': 100, 'obfuscate': False,
                       'protect': '', 'a_iso': 'dry', 'a_zone': 'off', 'a_rule': 'off', 'a_dns': 'on', 'a_pol': 'off', 'a_shp': 'off', 'a_inv': 'on', 'think': 'auto', 'small_model': False},
            'key_set': {'anthropic': False, 'openai': False, 'opnsense': True}, 'names': {'192.168.1.90': 'kamera-hof', '192.168.2.21': 'tv-iot', '192.168.1.91': 'drucker'},
            'act': {'proposals': [], 'actions': [], 'ready': True, 'api_ready': True},
            'improve': [{'prio': 'mittel', 'wo': 'dns', 'pair': '', 'title': 'DoH-Domains auch in Unbound sperren (HaGeZi)', 'ex': [], 'text': 'Dienste › Unbound DNS › Blocklisten: „DoH/VPN/TOR/Proxy Bypass“ einschalten.'}],
            'ready': '', 'last': {'t': now - 300, 'ok': True, 'provider': 'ollama', 'model': 'gpt-oss:20b', 'ms': 92800, 'why': 'interval', 'level': 'calm', 'model_level': 'calm',
                                  'summary': 'Keine Vorfälle. Die DNS-Sperren greifen: 1.281 Anfragen wurden umgeleitet.', 'findings': [], 'suggestions': [],
                                  'facts': [['Vorfälle', 'keine offenen'], ['DNS', 'Umleitung ja · DoH-Sperre ja · DoT-Sperre ja · 1281 Verbindungen abgefangen · nichts wird umgangen'], ['Lernmodus', '3 gelernt (2 stabil) · 11 lernen noch · 0 Abweichungen']],
                                  'since': now - 3900, 'small_model': False},
            'history': [{'t': now - 300 - i * 3600, 'ok': True, 'level': 'calm' if i != 3 else 'watch', 'summary': 'Lage %d' % i, 'ms': 90000, 'model': 'gpt-oss:20b', 'why': 'interval'} for i in range(8)],
            'today': {'calls': 31, 'cap': 100}, 'warnings': [], 'speed': {'gen': 8.75, 'read': 38.6, 'load': 25.9}, 'fail': None}


class FakeOpn:
    def __init__(self, key='K' * 40, secret='S' * 40, cn='opnsense.test'):
        self.key, self.secret = key, secret
        self.status = base_status(int(time.time()))
        self.inv = {'items': [], 'queue': [], 'running': None, 'today': 0, 'max_day': 6, 'next': ''}
        self.tasks, self.calls, self.next_id = [], [], 1
        self.mode = None                                     # None | 'drop' (close the connection) | '403' | '500' | 'html'
        self.next_scan = {'level': 'watch', 'summary': 'Ein Gerät fragt DNS an der Firewall vorbei.'}
        self.task_answer = {'answer': 'Das Gerät hat in den letzten 24 Stunden 12 Verbindungen zu einem neuen Land aufgebaut.', 'actions': []}
        self.lock = threading.Lock()
        self.cf, self.kf, self.fp = make_cert(cn)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self.cf, self.kf)
        fw = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def send(self, code, obj, raw=None):
                data = raw if raw is not None else json.dumps(obj).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json' if raw is None else 'text/html')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def go(self, method):
                n = int(self.headers.get('Content-Length', 0))
                form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode())) if n else {}
                if fw.mode == 'drop':
                    self.connection.close()
                    return
                if self.headers.get('Authorization') != 'Basic ' + base64.b64encode(('%s:%s' % (fw.key, fw.secret)).encode()).decode() or fw.mode == '403':
                    return self.send(403, {'status': 403, 'message': 'Authentication Failed'})
                if self.path != '/api/scdeck/stats/sarah':
                    return self.send(404, {'errorMessage': 'Endpoint not found'})
                if fw.mode == '500':
                    return self.send(500, {'errorMessage': 'Unexpected error, check log for details'})
                if fw.mode == 'html':
                    return self.send(200, None, b'<html>login</html>')
                with fw.lock:
                    fw.calls.append((method, form.get('cmd'), form.get('value')))
                    return self.send(200, fw.handle(method, form))

            def do_GET(self):
                self.go('GET')

            def do_POST(self):
                self.go('POST')
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.httpd.socket = self.ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.url = 'https://127.0.0.1:%d' % self.port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    # ---------------------------------------------------------------- helpers for the tests
    def rotate_cert(self):
        self.cf, self.kf, self.fp = make_cert('other.test')
        self.ctx.load_cert_chain(self.cf, self.kf)

    def stop(self):
        self.httpd.shutdown()

    def add_action(self, **e):
        e.setdefault('id', self.next_id)
        self.next_id = max(self.next_id, e['id']) + 1
        e.setdefault('t', int(time.time()))
        e.setdefault('who', 'S.A.R.A.H.')
        e.setdefault('result', 'ok')
        self.status['act']['actions'].append(e)
        return e

    # ---------------------------------------------------------------- the commands
    def handle(self, method, form):
        now = int(time.time())
        self.status['now'] = now
        if method == 'GET':
            return copy.deepcopy(self.status)
        cmd, value = form.get('cmd', ''), form.get('value', '')
        if cmd == 'analyze':
            self.status.update(running=True, state='think')

            def done():
                time.sleep(1.2)
                with self.lock:
                    s = self.next_scan
                    self.status['last'] = dict(self.status['last'], t=int(time.time()), ok=True, level=s['level'], model_level=s['level'], summary=s['summary'], why='manual')
                    self.status.update(running=False, level=s['level'], state='alert' if s['level'] == 'alert' else 'calm')
            threading.Thread(target=done, daemon=True).start()
            return copy.deepcopy(self.status)
        if cmd == 'tasks':
            for t in self.tasks:
                if t['status'] == 'queued' and now - t['t'] >= 1:
                    t.update(status='done', **copy.deepcopy(self.task_answer), model='gpt-oss:20b')
            return {'tasks': list(reversed(self.tasks))[:20]}
        if cmd == 'task':
            t = value.strip()
            if not t or len(t) > 1000:
                return {'error': 'invalid task'}
            if sum(1 for x in self.tasks if x['status'] == 'queued') >= 5:
                return {'error': 'Es warten schon 5 Aufträge'}
            item = {'id': len(self.tasks) + 1, 't': now, 'text': t, 'who': 'du', 'status': 'queued'}
            self.tasks.append(item)
            return {'ok': True, 'id': item['id']}
        if cmd == 'inv':
            return copy.deepcopy(self.inv)
        if cmd == 'invnow':
            if not re.fullmatch(r'[0-9a-fA-F.:]{3,45}', value):
                return {'error': 'invalid address'}
            self.inv['queue'].append({'key': 'manuell|' + value, 'kind': 'manuell', 'ip': value, 'anlass': 'von dir angestoßen', 'manual': True})
            return {'ok': True}
        if cmd in ('do', 'dismiss'):
            if not ACTION_ID.fullmatch(value):
                return {'error': 'invalid action id'}
            props = self.status['act']['proposals']
            hit = [p for p in props if p['id'] == value]
            if not hit:
                return {'error': 'Dieser Vorschlag gilt nicht mehr'}
            props.remove(hit[0])
            if cmd == 'do':
                self.add_action(type=hit[0]['type'], ip=hit[0].get('ip', ''), who='du', active=True, **({'descr': hit[0]['descr']} if hit[0].get('descr') else {}))
            return {'ok': True}
        if cmd == 'release':
            if not re.fullmatch(r'\d{1,6}', value):
                return {'error': 'invalid id'}
            hit = [e for e in self.status['act']['actions'] if e['id'] == int(value) and e.get('active')]
            if not hit:
                return {'error': 'Nur eigene, noch aktive Eingriffe von S.A.R.A.H. lassen sich hier aufheben'}
            hit[0]['active'] = False
            hit[0]['undone'] = True
            return {'ok': True}
        if cmd == 'noaus':
            for e in self.status['act']['actions']:
                e['active'] = False
            self.status['config'].update(mode='observe', a_iso='off', a_zone='off', a_rule='off', a_dns='off', a_pol='off', a_shp='off')
            return {'ok': True, 'n': 0}
        return {'error': 'invalid command'}
