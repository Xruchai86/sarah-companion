"""S.A.R.A.H. Companion - the server: login, a fixed list of commands to the firewall, push, and the web app itself.

Threat model in short: the container holds the firewall's key, so whoever gets into this UI can use it. Hence: a password (hashed, rate limited),
a session cookie (HttpOnly, SameSite=Strict, Secure on https), a header every state-changing call must carry (cross-site forms cannot send it),
a fixed command list instead of a proxy, strict headers (CSP), and a push subscription may only point to the known push services (no SSRF)."""
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import threading
import time
import urllib.parse

from flask import Flask, jsonify, request, send_from_directory, session
from flask.sessions import SecureCookieSessionInterface

from . import VERSION
from .notify import Poller, Pusher
from .tls import TLS
from .opn import Opn, OpnError, PinMismatch, fmt_fp
from .store import Store

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
PUSH_HOSTS = ('fcm.googleapis.com', '.push.services.mozilla.com', '.push.apple.com', '.notify.windows.com', '.push.microsoft.com')


class Sessions(SecureCookieSessionInterface):
    def get_cookie_secure(self, app):
        return bool(request.is_secure)                        # Secure on https (also behind a proxy that says so), plain http only for a local trial


class Throttle:
    """5 wrong passwords from one address -> locked for a minute, doubling up to 15 minutes"""

    def __init__(self, clock=time.time):
        self.clock, self.d, self.lock = clock, {}, threading.Lock()

    def check(self, who):
        with self.lock:
            e = self.d.get(who)
            return max(0, int(e['until'] - self.clock())) if e and e['until'] > self.clock() else 0

    def fail(self, who):
        with self.lock:
            e = self.d.setdefault(who, {'n': 0, 'until': 0, 'lock': 60})
            e['n'] += 1
            if e['n'] >= 5:
                e['until'] = self.clock() + e['lock']
                e['lock'] = min(e['lock'] * 2, 900)
                e['n'] = 0

    def ok(self, who):
        with self.lock:
            self.d.pop(who, None)


def push_host_ok(endpoint, allow_any=False):
    u = urllib.parse.urlparse(endpoint)
    if allow_any:
        return u.scheme in ('http', 'https') and bool(u.hostname)
    h = (u.hostname or '').lower()
    if u.scheme != 'https' or not h or len(endpoint) > 700:
        return False
    try:
        ipaddress.ip_address(h)
        return False                                          # an IP address is never a push service
    except ValueError:
        pass
    return any(h == p or h.endswith(p) if p.startswith('.') else h == p for p in PUSH_HOSTS)


def create_app(env=None, start_poller=True):
    env = os.environ if env is None else env
    pw = env.get('UI_PASSWORD', '')
    if len(pw) < 8:
        raise RuntimeError('UI_PASSWORD fehlt oder ist kürzer als 8 Zeichen.')
    for k in ('OPNSENSE_URL', 'OPNSENSE_KEY', 'OPNSENSE_SECRET'):
        if not env.get(k):
            raise RuntimeError('%s fehlt.' % k)
    app = Flask(__name__, static_folder=None)
    app.session_interface = Sessions()
    store = Store(env.get('DATA_DIR', '/data'))
    app.secret_key = store.secret_key()
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict', PERMANENT_SESSION_LIFETIME=30 * 86400, MAX_CONTENT_LENGTH=64 * 1024)
    if env.get('TRUST_PROXY') == '1':
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    opn = Opn(env['OPNSENSE_URL'], env['OPNSENSE_KEY'], env['OPNSENSE_SECRET'], store, verify=env.get('OPNSENSE_VERIFY', 'pin'))
    pusher = Pusher(store, store.dir, env.get('VAPID_SUBJECT', 'mailto:sarah@localhost.localdomain'), env.get('NTFY_URL', ''), env.get('NTFY_TOPIC', ''), env.get('NTFY_TOKEN', ''))
    poller = Poller(opn, store, pusher, interval=max(15, int(env.get('POLL_SECONDS', '60') or 60)))
    salt = secrets.token_bytes(16)
    pwhash = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 200_000)
    throttle = Throttle()
    allow_any_push = env.get('PUSH_ALLOW_ANY') == '1'                 # tests only
    app.extensions['sarah'] = {'opn': opn, 'store': store, 'pusher': pusher, 'poller': poller, 'throttle': throttle}

    def pw_ok(candidate):
        return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256', (candidate or '').encode(), salt, 200_000), pwhash)

    def err(msg, code=400, **kw):
        return jsonify(dict(error=msg, **kw)), code

    def guard(write=True):
        """None when allowed, else the error answer"""
        if not session.get('u'):
            return err('Bitte anmelden.', 401, kind='login')
        if write:
            if request.headers.get('X-Requested-With') != 'sarah' or not request.is_json:
                return err('Anfrage abgelehnt.', 403)
        return None

    def body():
        d = request.get_json(silent=True)
        return d if isinstance(d, dict) else {}

    def fw(cmd, value=''):
        """one command to the firewall; a failure becomes a clear answer for the app (our own input check: 400, anything on the way: 502)"""
        try:
            r = opn.command(cmd, value)
        except OpnError as e:
            return err(str(e), 400 if e.kind == 'input' else 502, kind=e.kind)
        if isinstance(r, dict) and r.get('error'):
            return err(str(r['error'])[:300], 400, kind='firewall')
        poller.st_t = 0                                           # the next look at the state asks the firewall again
        return jsonify({'ok': True, 'result': r})

    # ------------------------------------------------------------ headers on everything
    @app.after_request
    def headers(r):
        r.headers['Content-Security-Policy'] = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
                                                "manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        r.headers['X-Content-Type-Options'] = 'nosniff'
        r.headers['Referrer-Policy'] = 'no-referrer'
        r.headers['X-Frame-Options'] = 'DENY'
        r.headers['Permissions-Policy'] = 'camera=(), geolocation=(), microphone=(self)'
        if request.path.startswith('/api/'):
            r.headers['Cache-Control'] = 'no-store'
        return r

    # ------------------------------------------------------------ session
    @app.get('/healthz')
    def healthz():
        return jsonify({'ok': True, 'version': VERSION})

    @app.post('/api/login')
    def login():
        who = request.remote_addr or '?'
        wait = throttle.check(who)
        if wait:
            return err('Zu viele Versuche. Bitte in %d Sekunden erneut versuchen.' % wait, 429, wait=wait)
        if request.headers.get('X-Requested-With') != 'sarah':
            return err('Anfrage abgelehnt.', 403)
        if pw_ok(str(body().get('password', ''))):
            throttle.ok(who)
            session.clear()
            session['u'] = 1
            session.permanent = True
            return jsonify({'ok': True})
        throttle.fail(who)
        return err('Falsches Passwort.', 401)

    @app.post('/api/logout')
    def logout():
        session.clear()
        return jsonify({'ok': True})

    @app.get('/api/me')
    def me():
        return jsonify({'login': bool(session.get('u')), 'version': VERSION})

    # ------------------------------------------------------------ state for the app
    @app.get('/api/state')
    def state():
        g = guard(False)
        if g:
            return g
        stale = False
        err_msg = kind = None
        if time.time() - getattr(poller, 'st_t', 0) > 3:
            try:
                st = opn.status()
                try:
                    inv = opn.command('inv')
                except OpnError:
                    inv = poller.inv
                with poller.lock:
                    poller.st, poller.inv, poller.st_t = st, inv, time.time()
                    poller.health.update(ok=True, error=None, kind=None, t=int(time.time()), ok_t=int(time.time()))
            except OpnError as e:
                stale, err_msg, kind = True, str(e), e.kind
                with poller.lock:
                    poller.health.update(ok=False, error=err_msg, kind=kind, t=int(time.time()))
        pin = store.get_pin()
        return jsonify({'status': poller.st, 'inv': poller.inv, 'stale': stale or poller.st is None, 'error': err_msg, 'kind': kind, 'now': int(time.time()),
                        'health': poller.health, 'pin': ({'fp': fmt_fp(pin['fp']), 'since': pin['since']} if pin else None), 'verify': opn.verify,
                        'push': {'key': pusher.public_key(), 'devices': len(store.subs()), 'ntfy': bool(pusher.ntfy)}, 'prefs': store.prefs(), 'version': VERSION,
                        'host': opn.host, 'tls': TLS.public()})

    # ------------------------------------------------------------ commands (fixed list)
    def simple(cmd, field=None):
        g = guard(True)
        if g:
            return g
        return fw(cmd, str(body().get(field, '')) if field else '')

    @app.post('/api/analyze')
    def analyze():
        return simple('analyze')

    @app.post('/api/task')
    def task():
        return simple('task', 'text')

    @app.get('/api/tasks')
    def tasks():
        g = guard(False)
        return g or fw('tasks')

    @app.get('/api/inv')
    def inv():
        g = guard(False)
        return g or fw('inv')

    @app.post('/api/inv/now')
    def invnow():
        return simple('invnow', 'ip')

    @app.post('/api/do')
    def do():
        return simple('do', 'id')

    @app.post('/api/dismiss')
    def dismiss():
        return simple('dismiss', 'id')

    @app.post('/api/release')
    def release():
        return simple('release', 'id')

    @app.post('/api/noaus')
    def noaus():
        g = guard(True)
        if g:
            return g
        if body().get('confirm') is not True:
            return err('Not-Aus bitte bestätigen.')
        return fw('noaus')

    # ------------------------------------------------------------ settings, push, certificate
    @app.get('/api/prefs')
    def prefs_get():
        g = guard(False)
        return g or jsonify(store.prefs())

    @app.post('/api/prefs')
    def prefs_set():
        g = guard(True)
        if g:
            return g
        try:
            return jsonify(store.set_prefs(body()))
        except ValueError as e:
            return err(str(e))

    @app.post('/api/push/subscribe')
    def push_sub():
        g = guard(True)
        if g:
            return g
        s = body().get('subscription')
        k = (s or {}).get('keys') if isinstance(s, dict) else None
        b64 = re.compile(r'[A-Za-z0-9_\-]{10,200}={0,2}')
        if not (isinstance(s, dict) and isinstance(s.get('endpoint'), str) and isinstance(k, dict) and b64.fullmatch(str(k.get('p256dh', ''))) and b64.fullmatch(str(k.get('auth', '')))):
            return err('Ungültiges Abo.')
        if not push_host_ok(s['endpoint'], allow_any_push):
            return err('Dieser Push-Dienst wird nicht akzeptiert.')
        sid = store.add_sub({'endpoint': s['endpoint'], 'keys': {'p256dh': k['p256dh'], 'auth': k['auth']}}, request.headers.get('User-Agent', ''))
        return jsonify({'ok': True, 'id': sid, 'devices': len(store.subs())})

    @app.post('/api/push/unsubscribe')
    def push_unsub():
        g = guard(True)
        if g:
            return g
        ep = body().get('endpoint')
        return jsonify({'ok': True, 'removed': store.remove_sub(endpoint=ep) if isinstance(ep, str) else 0, 'devices': len(store.subs())})

    @app.post('/api/push/test')
    def push_test():
        g = guard(True)
        if g:
            return g
        from .notify import note
        r = pusher.send(note('test', 'watch', 'S.A.R.A.H. Companion', 'Test: Meldungen kommen an.', 'more', 'test'))
        return jsonify({'ok': True, **r})

    @app.post('/api/pin/trust')
    def pin_trust():
        g = guard(True)
        if g:
            return g
        who = request.remote_addr or '?'
        if throttle.check(who):
            return err('Zu viele Versuche.', 429)
        if not pw_ok(str(body().get('password', ''))):
            throttle.fail(who)
            return err('Falsches Passwort.', 401)
        try:
            opn.trust_now()
        except OpnError as e:
            return err(str(e), 502, kind=e.kind)
        with poller.lock:
            poller.st_t = 0
        return jsonify({'ok': True, 'fp': fmt_fp(store.get_pin()['fp'])})

    # ------------------------------------------------------------ the web app
    @app.get('/')
    def index():
        r = send_from_directory(STATIC, 'index.html')
        r.headers['Cache-Control'] = 'no-cache'
        return r

    @app.get('/<path:name>')
    def static_file(name):
        if name.startswith('api/') or '..' in name:
            return err('Nicht gefunden.', 404)
        r = send_from_directory(STATIC, name)
        r.headers['Cache-Control'] = 'no-cache' if name in ('sw.js', 'manifest.webmanifest', 'index.html') else 'public, max-age=3600'
        if name == 'sw.js':
            r.headers['Service-Worker-Allowed'] = '/'
        return r

    if start_poller:
        poller.start()
    return app
