"""S.A.R.A.H.'s model questions, asked from here (os-scdeck jobs.py, 0.63+): the firewall keeps the questions, the check of every answer
against its facts, the level rules and every action; the Companion only does the waiting for the model.

  every 20 s   `job` - the firewall answers with the next question (an analysis that is due, an investigation) and the model settings
  then         the question goes to the local Ollama (the address from the firewall's S.A.R.A.H. settings; only private addresses, no
               redirects, no proxy - the same rules as on the firewall), the reply goes back with `jobdone`; an investigation answers with
               its next question until it is done
Cloud models are not asked from here: their keys stay on the firewall."""
import ipaddress
import json
import logging
import re
import socket
import time
import urllib.error
import urllib.request

log = logging.getLogger("sarah.runner")
EVERY = 20


def host_is_private(url):
    m = re.match(r'https?://(\[[0-9a-fA-F:]+\]|[^/:]+)', url or '')
    if not m:
        return False
    try:
        infos = socket.getaddrinfo(m.group(1).strip('[]'), None)
    except OSError:
        return False
    addrs = {i[4][0].split('%')[0] for i in infos}
    ok = lambda a: ipaddress.ip_address(a).is_private or ipaddress.ip_address(a).is_loopback or ipaddress.ip_address(a).is_link_local
    return bool(addrs) and all(ok(a) for a in addrs)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _post(url, body, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json', 'User-Agent': 'sarah-companion/runner'}, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            return json.loads(r.read(6 * 1024 * 1024))
    except urllib.error.HTTPError as e:
        raise RuntimeError('HTTP %d von %s' % (e.code, re.sub(r'^https?://', '', url).split('/')[0]))
    except socket.timeout:
        raise RuntimeError('keine vollständige Antwort nach %d s (Zeitlimit)' % timeout)
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError('keine Verbindung zu %s (%s)' % (re.sub(r'^https?://', '', url).split('/')[0], str(getattr(e, 'reason', e))[:80]))
    except ValueError:
        raise RuntimeError('keine gültige JSON-Antwort')


def ask_ollama(job):
    """-> (reply text, Ollama's counters). The request is the one the firewall would send itself (sarah.py _provider_call)."""
    m = job['model']
    base = (m.get('url') or '').rstrip('/')
    if not host_is_private(base):
        raise RuntimeError('Der lokale Anbieter muss eine private Adresse haben (geprüft: %s)' % base)
    body = {'model': m['model'], 'stream': False, 'format': 'json', 'options': {'temperature': m.get('temperature', 0.2), 'num_ctx': m.get('num_ctx', 8192), 'num_predict': m.get('num_predict', 900)},
            'messages': [{'role': 'system', 'content': job['system']}, {'role': 'user', 'content': job['user']}]}
    if m.get('think') is not None:
        body['think'] = m['think']
    limit = max(30, int(job.get('limit') or 900))
    try:
        r = _post(base + '/api/chat', body, limit)
    except RuntimeError as e:
        if 'think' not in body or 'HTTP 400' not in str(e):
            raise
        body.pop('think')                                          # an Ollama or model without that option: once more without it
        r = _post(base + '/api/chat', body, limit)
    meta = {k: r.get(k) for k in ('eval_count', 'eval_duration', 'prompt_eval_count', 'prompt_eval_duration', 'load_duration') if k in r}
    return (r.get('message') or {}).get('content', ''), meta


class Runner:
    def __init__(self, ask=ask_ollama):
        self.ask = ask
        self.c = {'jobs': 0, 'analyses': 0, 'investigations': 0, 'failed': 0, 'last': 0, 'error': None, 'why': None, 'busy': None}

    def step(self, opn):
        """one look for work; a job is followed through all its questions"""
        r = opn.command('job')
        self.c['why'] = (r or {}).get('why') if isinstance(r, dict) else None
        job = (r or {}).get('job') if isinstance(r, dict) else None
        while job:
            self.c['busy'] = {'kind': job.get('kind'), 'stage': job.get('stage'), 'since': int(time.time())}
            t0 = time.time()
            answer = {'id': job['id']}
            try:
                reply, meta = self.ask(job)
                answer.update(reply=reply, meta=meta)
                self.c['error'] = None
            except Exception as e:
                answer['error'] = str(e)[:300]
                self.c.update(failed=self.c['failed'] + 1, error=answer['error'])
            answer['ms'] = int((time.time() - t0) * 1000)
            r = opn.command('jobdone', json.dumps(answer, ensure_ascii=False))
            self.c['jobs'] += 1
            self.c['last'] = int(time.time())
            if isinstance(r, dict) and r.get('done'):
                self.c['analyses' if job.get('kind') == 'analyze' else 'investigations'] += 1
            job = r.get('job') if isinstance(r, dict) else None
        self.c['busy'] = None
        return r

    def run(self, opn, stop):
        while not stop.wait(EVERY):
            try:
                self.step(opn)
            except Exception as e:                                   # the firewall is away: it asks the model itself after 5 minutes
                self.c['error'] = str(e)[:200]
                log.warning("runner: %s", e)
