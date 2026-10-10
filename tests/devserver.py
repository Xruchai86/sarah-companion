"""Starts the app against the fake firewall for the browser tests, plus a small control port to change what the 'firewall' says.
Prints one JSON line with both ports. Test use only (PUSH_ALLOW_ANY is off; the control port listens on 127.0.0.1)."""
import json, os, sys, tempfile, threading, copy, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cheroot import wsgi
from tests.fake_opn import FakeOpn, base_status
from app.main import create_app

fw = FakeOpn()
data = tempfile.mkdtemp()
env = {'UI_PASSWORD': 'ein-langes-passwort', 'OPNSENSE_URL': fw.url, 'OPNSENSE_KEY': fw.key, 'OPNSENSE_SECRET': fw.secret, 'DATA_DIR': data}
app = create_app(env, start_poller=False)
ext = app.extensions['sarah']
APP_PORT = int(os.environ.get('APP_PORT', '0')) or 18090


def merge(a, b):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            merge(a[k], v)
        else:
            a[k] = v


class Ctl(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        c = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        cmd, out = c['cmd'], {'ok': True}
        with fw.lock:
            if cmd == 'status': merge(fw.status, c['patch'])
            elif cmd == 'proposals': fw.status['act']['proposals'] = c['list']
            elif cmd == 'action': fw.add_action(**c['entry'])
            elif cmd == 'inv': fw.inv = c['value']
            elif cmd == 'mode': fw.mode = c['value']
            elif cmd == 'rotate': fw.rotate_cert()
            elif cmd == 'next_scan': fw.next_scan = c['value']
            elif cmd == 'task_answer': fw.task_answer = c['value']
            elif cmd == 'reset':
                fw.status = base_status(int(time.time())); fw.tasks, fw.calls, fw.mode = [], [], None
                fw.inv = {'items': [], 'queue': [], 'running': None, 'today': 0, 'max_day': 6, 'next': ''}
                from app.store import DEFAULT_PREFS
                ext['store'].set_prefs(copy.deepcopy(DEFAULT_PREFS)); ext['store'].set_seen({})
                for sub in ext['store'].subs(): ext['store'].remove_sub(sid=sub['id'])
            elif cmd == 'calls': out['calls'] = fw.calls
            elif cmd == 'prefs': out['prefs'] = ext['store'].prefs()
            elif cmd == 'subs': out['subs'] = ext['store'].subs()
            elif cmd == 'invalidate': ext['poller'].st_t = 0
        data_ = json.dumps(out).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(data_))); self.end_headers(); self.wfile.write(data_)


ctl = ThreadingHTTPServer(('127.0.0.1', 0), Ctl)
threading.Thread(target=ctl.serve_forever, daemon=True).start()
print(json.dumps({'app': APP_PORT, 'ctl': ctl.server_address[1]}), flush=True)
srv = wsgi.Server(('127.0.0.1', APP_PORT), app, numthreads=8, server_name='sarah')
srv.safe_start()
