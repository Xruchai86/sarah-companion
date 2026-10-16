"""The Companion asks the model for S.A.R.A.H. (firewall jobs.py): a job is followed through all its questions, a model failure goes back as
an error (the firewall counts it), the request to Ollama is the firewall's own, only private model addresses, no redirects.
The firewall's half is tested end to end in the DECK's t_jobs."""
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
from app.runner import Runner, ask_ollama, host_is_private
from app.opn import check_command, OpnError


class Fw:
    def __init__(self, jobs):
        self.jobs, self.done = list(jobs), []

    def command(self, cmd, value=''):
        check_command(cmd, value)
        if cmd == 'job':
            return {'job': self.jobs.pop(0) if self.jobs else None, 'why': 'nothing'}
        a = json.loads(value)
        self.done.append(a)
        nxt = self.jobs.pop(0) if self.jobs and self.jobs[0].get('id') == a['id'] else None
        return {'ok': True, 'job': nxt} if nxt else {'ok': True, 'done': True}


def job(i='a1', kind='invest', stage='plan'):
    return {'id': i, 'kind': kind, 'stage': stage, 'system': 'S', 'user': 'U', 'limit': 60, 'model': {'url': 'http://127.0.0.1:1', 'model': 'm'}}


def test_a_job_is_followed_through_its_questions():
    asked = []
    r = Runner(ask=lambda j: (asked.append(j['stage']) or '{"x": 1}', {'eval_count': 5}))
    fw = Fw([job(stage='plan'), job(stage='judge')])
    r.step(fw)
    assert asked == ['plan', 'judge'] and [d['reply'] for d in fw.done] == ['{"x": 1}'] * 2 and fw.done[0]['meta'] == {'eval_count': 5}
    assert r.c['jobs'] == 2 and r.c['investigations'] == 1 and r.c['busy'] is None


def test_a_model_failure_goes_back_as_an_error():
    def boom(j):
        raise RuntimeError('keine Verbindung zu 192.168.0.45:11434')
    r = Runner(ask=boom)
    fw = Fw([job('b1', 'analyze', '')])
    r.step(fw)
    assert fw.done[0]['error'].startswith('keine Verbindung') and 'reply' not in fw.done[0] and r.c['failed'] == 1 and r.c['analyses'] == 1


def test_nothing_to_do():
    r = Runner(ask=lambda j: pytest.fail('no job, no question'))
    assert r.step(Fw([]))['why'] == 'nothing' and r.c['jobs'] == 0


class Ollama(BaseHTTPRequestHandler):
    seen = []
    def log_message(self, *a): pass
    def do_POST(self):
        b = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        Ollama.seen.append((self.path, b))
        if b.get('think') is not None and b['model'] == 'old':
            self.send_response(400); self.end_headers(); return
        out = json.dumps({'message': {'content': '{"ok": true}'}, 'eval_count': 9, 'eval_duration': 10**9}).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out)


def test_the_request_to_ollama():
    srv = ThreadingHTTPServer(('127.0.0.1', 0), Ollama); threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = 'http://127.0.0.1:%d' % srv.server_address[1]
        reply, meta = ask_ollama({'system': 'S', 'user': 'U', 'limit': 30, 'model': {'url': url, 'model': 'gpt-oss:20b', 'think': 'low', 'num_predict': 1600, 'num_ctx': 8192, 'temperature': 0.2}})
        path, b = Ollama.seen[-1]
        assert reply == '{"ok": true}' and meta == {'eval_count': 9, 'eval_duration': 10**9} and path == '/api/chat'
        assert b == {'model': 'gpt-oss:20b', 'stream': False, 'format': 'json', 'options': {'temperature': 0.2, 'num_ctx': 8192, 'num_predict': 1600},
                     'messages': [{'role': 'system', 'content': 'S'}, {'role': 'user', 'content': 'U'}], 'think': 'low'}
        ask_ollama({'system': 'S', 'user': 'U', 'limit': 30, 'model': {'url': url, 'model': 'old', 'think': True}})
        assert 'think' in Ollama.seen[-2][1] and 'think' not in Ollama.seen[-1][1], 'a model without think: asked once more without it'
    finally:
        srv.shutdown()


def test_only_private_model_addresses():
    assert host_is_private('http://192.168.0.45:11434') and host_is_private('http://127.0.0.1:11434')
    assert not host_is_private('http://8.8.8.8:11434') and not host_is_private('ftp://x') and not host_is_private('')
    with pytest.raises(RuntimeError):
        ask_ollama({'system': 'S', 'user': 'U', 'limit': 5, 'model': {'url': 'http://8.8.8.8:11434', 'model': 'm'}})


def test_the_commands_and_their_limits():
    assert check_command('job') == ''
    with pytest.raises(OpnError):
        check_command('jobdone', 'x' * (4 * 1024 * 1024 + 1))
