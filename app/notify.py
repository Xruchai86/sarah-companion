"""When does S.A.R.A.H. tap you on the shoulder?

  scan           a scan has FINISHED and found something (level watch or alert, at least the level you chose). A calm scan stays silent.
  incident       an incident opens (also between scans)
  action         she acted on her own (isolated a device, switched off a rule ...) - with the hint that a veto is possible
  investigation  an investigation came out "suspicious" or "dangerous"
  proposal       something is waiting for your decision
  offline        the firewall has been out of reach for 10 minutes (and when it is back); a CHANGED certificate at once
Quiet hours: only an alarm passes, the rest is held and arrives as ONE digest when they end.
decide() is a pure function (no network, no clock): it gets what was seen last time and what the firewall says now."""
import base64
import copy
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request

from .opn import OpnError

log = logging.getLogger('sarah')
LV = {'calm': 0, 'watch': 1, 'alert': 2}
LEVEL_TEXT = {'calm': 'Ruhig', 'watch': 'Beobachten', 'alert': 'Alarm'}
ACT_TEXT = {'isolate': 'Gerät isoliert', 'rule_off': 'Regel ausgeschaltet', 'zone_expect': 'Zonen-Richtung gelernt', 'dns': 'DNS-Härtung', 'policy': 'Geräte-Richtlinie',
            'shaper': 'Traffic-Shaping'}
VERDICT = {'verdaechtig': 'verdächtig', 'gefaehrlich': 'gefährlich'}
OFFLINE_AFTER = 600


def clip(s, n):
    s = ' '.join(str(s or '').split())
    return s if len(s) <= n else s[:n - 1] + '…'


def label(ip, names):
    n = (names or {}).get(ip)
    return '%s (%s)' % (n, ip) if n else (ip or '?')


def proposal_title(p, names=None):
    t = p.get('type')
    if t == 'isolate':
        return '%s isolieren (24 h)' % label(p.get('ip'), names)
    if t == 'rule_off':
        return 'Regel „%s“ ausschalten' % clip(p.get('descr'), 60)
    if t == 'dns':
        return 'DNS: %s' % clip(p.get('descr'), 70)
    if t == 'policy':
        return 'Richtlinie für %s' % label(p.get('ip'), names)
    if t == 'shaper':
        return 'Traffic-Shaping einrichten'
    return clip(p.get('descr') or p.get('id'), 70)


def minutes(hhmm):
    h, m = hhmm.split(':')
    return int(h) * 60 + int(m)


def in_quiet(prefs, now):
    q = prefs.get('quiet') or {}
    if not q.get('on'):
        return False
    lt = time.localtime(now)
    cur, a, b = lt.tm_hour * 60 + lt.tm_min, minutes(q['from']), minutes(q['to'])
    return (a <= cur < b) if a <= b else (cur >= a or cur < b)


def note(kind, level, title, body, tab='core', tag=None):
    return {'kind': kind, 'level': level, 'title': clip(title, 90), 'body': clip(body, 220), 'tab': tab, 'tag': tag or kind}


def decide(seen, st, inv, prefs, now, error=None, error_kind=None):
    """-> (notes to send now, new seen). `st` is the status of the firewall (or None when it could not be read, then `error` says why)."""
    seen = copy.deepcopy(seen or {})
    ev = prefs.get('events') or {}
    notes = []
    held = list(seen.get('held') or [])

    # ------------------------------------------------------------ the firewall cannot be read
    if st is None:
        if error_kind == 'pin':
            if not seen.get('pin_sent') and ev.get('offline', True):
                notes.append(note('offline', 'alert', 'Zertifikat der Firewall hat sich geändert', 'Es wird nichts mehr gesendet, bis du es in der App bestätigst. Sei vorsichtig: das kann auch ein Angriff im Netz sein.', 'more', 'cert'))
                seen['pin_sent'] = True
        else:
            seen.setdefault('offline_since', now)
            if now - seen['offline_since'] >= OFFLINE_AFTER and not seen.get('offline_sent') and ev.get('offline', True):
                notes.append(note('offline', 'watch', 'Firewall nicht erreichbar', clip(error, 160) or 'Seit über 10 Minuten keine Verbindung.', 'more', 'offline'))
                seen['offline_sent'] = True
        return _quiet_filter(notes, held, seen, prefs, now)
    if seen.get('offline_sent') and ev.get('offline', True):
        notes.append(note('offline', 'watch', 'Firewall wieder erreichbar', 'Die Verbindung steht wieder.', 'more', 'offline'))
    for k in ('offline_since', 'offline_sent', 'pin_sent'):
        seen.pop(k, None)

    first = not seen.get('init')
    seen['init'] = True                                           # the first look only sets the baseline: no flood of old news
    act = (st.get('act') or {}) if isinstance(st.get('act'), dict) else {}
    names = st.get('names') if isinstance(st.get('names'), dict) else {}

    # ------------------------------------------------------------ 1. a scan finished
    last = st.get('last') or {}
    if last.get('ok') and int(last.get('t') or 0) > int(seen.get('last_t') or 0):
        lvl = last.get('level') or 'calm'
        if not first and ev.get('scan', True) and lvl != 'calm' and LV.get(lvl, 0) >= LV.get(prefs.get('level', 'watch'), 1):
            body = last.get('summary') or ''
            if last.get('level_note'):
                body = '%s (%s)' % (body, last['level_note'])
            notes.append(note('scan', lvl, 'S.A.R.A.H.: %s' % LEVEL_TEXT.get(lvl, lvl), body, 'core', 'scan'))
        seen['last_t'] = int(last['t'])

    # ------------------------------------------------------------ 2. an incident opens
    inc = bool(st.get('open_incident'))
    if inc and not seen.get('incident') and not first and ev.get('incident', True):
        notes.append(note('incident', 'alert', 'Offener Vorfall', 'Mehrere Quellen belasten dasselbe Gerät. Details in der App.', 'core', 'incident'))
    seen['incident'] = inc

    # ------------------------------------------------------------ 3. she acted on her own
    top = int(seen.get('action_id') or 0)
    for e in sorted((x for x in act.get('actions') or [] if isinstance(x, dict) and isinstance(x.get('id'), int)), key=lambda x: x['id']):
        if e['id'] <= top:
            continue
        top = max(top, e['id'])
        if first or e.get('who') != 'S.A.R.A.H.' or not ev.get('action', True):
            continue
        if e.get('result') == 'ok' and e.get('type') in ACT_TEXT:
            notes.append(note('action', 'watch', 'S.A.R.A.H. hat gehandelt: %s' % ACT_TEXT[e['type']], '%s. Ein Veto ist in der App möglich.' % clip(e.get('descr') or label(e.get('ip'), names), 150), 'actions', 'action-%d' % e['id']))
        elif e.get('result') == 'failed':
            notes.append(note('action', 'watch', 'Eingriff fehlgeschlagen', '%s: %s' % (clip(e.get('descr'), 80), clip(e.get('error'), 120)), 'actions', 'action-%d' % e['id']))
    seen['action_id'] = top

    # ------------------------------------------------------------ 4. an investigation found something
    topi = int(seen.get('inv_id') or 0)
    for it in sorted((x for x in (inv or {}).get('items') or [] if isinstance(x, dict) and isinstance(x.get('id'), int)), key=lambda x: x['id']):
        if it['id'] <= topi:
            continue
        topi = max(topi, it['id'])
        if first or not ev.get('investigation', True) or not it.get('ok') or it.get('urteil') not in VERDICT:
            continue
        notes.append(note('investigation', 'alert' if it['urteil'] == 'gefaehrlich' else 'watch', 'Untersuchung: %s %s' % (clip(it.get('name') or it.get('ip'), 40), VERDICT[it['urteil']]),
                          it.get('begruendung') or it.get('anlass') or '', 'inv', 'inv-%d' % it['id']))
    seen['inv_id'] = topi

    # ------------------------------------------------------------ 5. something waits for you
    props = [p for p in act.get('proposals') or [] if isinstance(p, dict) and p.get('id') and not p.get('blocked_reason')]
    ids = [p['id'] for p in props]
    fresh = [p for p in props if p['id'] not in (seen.get('proposals') or [])]
    if fresh and not first and ev.get('proposal', True):
        notes.append(note('proposal', 'watch', 'Wartet auf dich: %s' % ('%d Vorschläge' % len(props) if len(props) > 1 else '1 Vorschlag'),
                          '; '.join(proposal_title(p, names) for p in props[:3]) + (' …' if len(props) > 3 else ''), 'core', 'proposal'))
    seen['proposals'] = ids

    return _quiet_filter(notes, held, seen, prefs, now)


def _quiet_filter(notes, held, seen, prefs, now):
    quiet = in_quiet(prefs, now)
    out = []
    for n in notes:
        if quiet and n['level'] != 'alert':
            held.append({'title': n['title'], 'tag': n['tag']})
        else:
            out.append(n)
    if not quiet and held:
        counts = {}
        for h in held:
            counts[h['title']] = counts.get(h['title'], 0) + 1
        parts = ['%s%s' % (t, ' (×%d)' % c if c > 1 else '') for t, c in counts.items()]
        out.append(note('digest', 'watch', 'Über Nacht: %d Meldung%s' % (len(held), '' if len(held) == 1 else 'en'), '; '.join(parts[:4]) + (' …' if len(parts) > 4 else ''), 'core', 'digest'))
        held = []
    seen['held'] = held[-20:]
    return out, seen


# ====================================================================== delivery
class Pusher:
    """web push (VAPID) to every subscribed device and, if configured, ntfy. A device that is gone (404/410) is forgotten."""

    def __init__(self, store, folder, subject, ntfy_url='', ntfy_topic='', ntfy_token=''):
        from py_vapid import Vapid
        self.store, self.subject = store, subject
        self.ntfy = (ntfy_url.rstrip('/'), ntfy_topic, ntfy_token) if ntfy_url and ntfy_topic else None
        pem = os.path.join(folder, 'vapid_private.pem')
        if not os.path.exists(pem):
            v = Vapid()
            v.generate_keys()
            v.save_key(pem)
            os.chmod(pem, 0o600)
        self.pem = pem
        self.vapid = Vapid.from_file(pem)

    def public_key(self):
        from cryptography.hazmat.primitives import serialization
        raw = self.vapid.public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()

    def send(self, n):
        from pywebpush import webpush, WebPushException
        payload = json.dumps({'title': n['title'], 'body': n['body'], 'tag': n['tag'], 'kind': n['kind'], 'level': n['level'], 'tab': n['tab'], 't': int(time.time())}, ensure_ascii=False)
        res = {'sent': 0, 'removed': 0, 'errors': [], 'ntfy': None}
        for s in self.store.subs():
            try:
                webpush(subscription_info=s['sub'], data=payload, vapid_private_key=self.vapid, vapid_claims={'sub': self.subject}, ttl=43200, timeout=10,
                        headers={'Urgency': 'high' if n['level'] == 'alert' else 'normal'})
                res['sent'] += 1
            except WebPushException as e:
                code = getattr(getattr(e, 'response', None), 'status_code', None)
                if code in (404, 410):
                    res['removed'] += self.store.remove_sub(sid=s['id'])
                else:
                    res['errors'].append('HTTP %s' % code if code else type(e).__name__)
            except Exception as e:                                   # one broken device must not stop the others
                res['errors'].append(type(e).__name__)
        if self.ntfy:
            res['ntfy'] = self._ntfy(n)
        if res['errors']:
            log.warning('push: %s', res['errors'][:3])
        return res

    def _ntfy(self, n):
        url, topic, token = self.ntfy
        body = {'topic': topic, 'title': n['title'], 'message': n['body'] or n['title'], 'priority': 4 if n['level'] == 'alert' else 3,
                'tags': ['rotating_light'] if n['level'] == 'alert' else ['eyes']}
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method='POST', headers={'Content-Type': 'application/json'})
        if token:
            req.add_header('Authorization', 'Bearer ' + token)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except (urllib.error.URLError, OSError) as e:
            log.warning('ntfy: %s', type(e).__name__)
            return None


# ====================================================================== the clock that looks at the firewall
class Poller:
    def __init__(self, opn, store, pusher, interval=60, clock=time.time):
        self.opn, self.store, self.pusher, self.interval, self.clock = opn, store, pusher, interval, clock
        self.health = {'ok': None, 't': 0, 'error': None, 'kind': None, 'ok_t': 0}
        self.st = None
        self.inv = None
        self.st_t = 0                                             # when `st` was read (real time): the app may use it for a few seconds
        self.stop = threading.Event()
        self.lock = threading.Lock()

    def tick(self):
        now = int(self.clock())
        st = inv = err = kind = None
        try:
            st = self.opn.status()
            try:
                inv = self.opn.command('inv')
            except OpnError:
                inv = None
        except OpnError as e:
            err, kind = str(e), e.kind
        with self.lock:
            notes, seen = decide(self.store.seen(), st, inv, self.store.prefs(), now, err, kind)
            self.store.set_seen(seen)
            self.health = {'ok': st is not None, 't': now, 'error': err, 'kind': kind, 'ok_t': now if st is not None else self.health.get('ok_t', 0)}
            if st is not None:
                self.st, self.inv, self.st_t = st, inv, time.time()
        for n in notes:
            self.pusher.send(n)
        return notes

    def run(self):
        while not self.stop.wait(self.interval):
            try:
                self.tick()
            except Exception:                                        # the clock must never die
                log.exception('poll')

    def start(self):
        t = threading.Thread(target=self.run, daemon=True, name='poller')
        t.start()
        return t
