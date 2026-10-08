"""Starts the app the way the container does (python -m app, configuration only through environment variables) and walks through it once."""
import http.cookiejar, json, os, signal, stat, subprocess, sys, tempfile, time, urllib.request
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests.fake_opn import FakeOpn

fw = FakeOpn(); data = tempfile.mkdtemp(); port = 18095
env = dict(os.environ, OPNSENSE_URL=fw.url, OPNSENSE_KEY=fw.key, OPNSENSE_SECRET=fw.secret, UI_PASSWORD='ein-langes-passwort', DATA_DIR=data, PORT=str(port), POLL_SECONDS='15', LOG_LEVEL='WARNING')
p = subprocess.Popen([sys.executable, '-m', 'app'], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
BAD = []
def ok(c, m):
    print(('  OK     ' if c else '  FEHLER ') + m)
    if not c: BAD.append(m)
try:
    for _ in range(40):
        try:
            h = json.loads(urllib.request.urlopen('http://127.0.0.1:%d/healthz' % port, timeout=2).read()); break
        except Exception: time.sleep(0.25)
    else:
        raise SystemExit('Server kam nicht hoch: ' + p.stdout.read(2000).decode())
    ok(h['ok'] and h['version'], 'der Einstieg „python -m app“ startet und antwortet auf /healthz (Version %s)' % h['version'])
    jar = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    def call(path, data=None, method=None):
        r = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path), data=json.dumps(data).encode() if data is not None else None, method=method or ('POST' if data is not None else 'GET'),
                                   headers={'X-Requested-With': 'sarah', 'Content-Type': 'application/json'})
        return json.loads(op.open(r, timeout=10).read())
    ok(call('/api/login', {'password': 'ein-langes-passwort'})['ok'], 'Anmeldung')
    s = call('/api/state')
    ok(s['status']['level'] == 'calm' and s['pin']['fp'] and s['push']['key'], 'Stand von der Firewall, Zertifikat gemerkt, Push-Schlüssel erzeugt')
    ok(call('/api/task', {'text': 'Rauchtest'})['ok'], 'ein Auftrag geht durch')
    files = {f: oct(os.stat(os.path.join(data, f)).st_mode & 0o777) for f in os.listdir(data)}
    ok({'state.json', 'secret.key', 'vapid_private.pem'} <= set(files) and all(v == '0o600' for v in files.values()), 'Geheimnisse und Zustand liegen nur im Datenordner, alle mit Rechten 600: %s' % files)
    ok(fw.key not in open(os.path.join(data, 'state.json')).read() and fw.secret not in open(os.path.join(data, 'state.json')).read(), 'der Firewall-Schlüssel steht NICHT in den Daten (er bleibt in der Umgebung)')
    time.sleep(16)
    ok(p.poll() is None, 'der Abfrage-Takt läuft im Hintergrund, ohne dass der Prozess stirbt')
finally:
    p.send_signal(signal.SIGTERM); fw.stop()
print('\nERGEBNIS:', 'ALLE PRÜFUNGEN BESTANDEN' if not BAD else '%d FEHLER' % len(BAD)); sys.exit(1 if BAD else 0)
