"""Everything that has to survive a restart lives in one folder (/data): a JSON file written atomically (temp file + rename, mode 600),
the session secret and the VAPID key for web push. Nothing here is the firewall's key: that stays in the environment."""
import copy
import json
import os
import re
import secrets
import threading
import time

LEVELS = ('watch', 'alert')
EVENTS = ('scan', 'incident', 'action', 'investigation', 'proposal', 'offline')
DEFAULT_PREFS = {
    'level': 'watch',                                   # the lowest level a FINISHED SCAN may push (calm never pushes)
    'events': {k: True for k in EVENTS},
    'quiet': {'on': False, 'from': '22:00', 'to': '07:00'},     # during quiet hours only an alarm gets through, the rest comes as one digest
}
HHMM = re.compile(r'([01]\d|2[0-3]):[0-5]\d')


def clean_prefs(p, base=None):
    """validated copy; unknown keys are dropped, wrong values raise ValueError"""
    out = copy.deepcopy(base or DEFAULT_PREFS)
    if not isinstance(p, dict):
        raise ValueError('Einstellungen fehlen')
    if 'level' in p:
        if p['level'] not in LEVELS:
            raise ValueError('Ungültige Stufe')
        out['level'] = p['level']
    if isinstance(p.get('events'), dict):
        for k, v in p['events'].items():
            if k in EVENTS:
                if not isinstance(v, bool):
                    raise ValueError('Ungültiger Wert')
                out['events'][k] = v
    if isinstance(p.get('quiet'), dict):
        q = p['quiet']
        if 'on' in q:
            if not isinstance(q['on'], bool):
                raise ValueError('Ungültiger Wert')
            out['quiet']['on'] = q['on']
        for k in ('from', 'to'):
            if k in q:
                if not isinstance(q[k], str) or not HHMM.fullmatch(q[k]):
                    raise ValueError('Uhrzeit bitte als HH:MM')
                out['quiet'][k] = q[k]
    return out


class Store:
    def __init__(self, folder):
        self.dir = folder
        os.makedirs(folder, exist_ok=True)
        self.path = os.path.join(folder, 'state.json')
        self.lock = threading.RLock()

    # ---------------------------------------------------------------- the state file
    def _load(self):
        try:
            with open(self.path) as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, d):
        tmp = self.path + '.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(d, f, separators=(',', ':'))
        os.replace(tmp, self.path)

    def _update(self, fn):
        with self.lock:
            d = self._load()
            r = fn(d)
            self._save(d)
            return r

    # ---------------------------------------------------------------- certificate pin
    def get_pin(self):
        return self._load().get('pin')

    def set_pin(self, fp):
        self._update(lambda d: d.__setitem__('pin', {'fp': fp, 'since': int(time.time())}))

    # ---------------------------------------------------------------- push subscriptions (one per browser / device)
    def subs(self):
        return list(self._load().get('subs', []))

    def add_sub(self, sub, ua=''):
        ep = sub['endpoint']

        def f(d):
            lst = [s for s in d.get('subs', []) if s['sub']['endpoint'] != ep]
            sid = secrets.token_hex(6)
            lst.append({'id': sid, 'sub': sub, 'ua': ua[:120], 't': int(time.time())})
            d['subs'] = lst[-20:]
            return sid
        return self._update(f)

    def remove_sub(self, endpoint=None, sid=None):
        def f(d):
            before = len(d.get('subs', []))
            d['subs'] = [s for s in d.get('subs', []) if not ((endpoint and s['sub']['endpoint'] == endpoint) or (sid and s['id'] == sid))]
            return before - len(d['subs'])
        return self._update(f)

    # ---------------------------------------------------------------- preferences and what was already reported
    def prefs(self):
        try:
            return clean_prefs(self._load().get('prefs') or {})
        except ValueError:
            return copy.deepcopy(DEFAULT_PREFS)

    def set_prefs(self, p):
        new = clean_prefs(p, self.prefs())
        self._update(lambda d: d.__setitem__('prefs', new))
        return new

    def seen(self):
        return self._load().get('seen') or {}

    def set_seen(self, s):
        self._update(lambda d: d.__setitem__('seen', s))

    # ---------------------------------------------------------------- secrets that are made once
    def secret_key(self):
        p = os.path.join(self.dir, 'secret.key')
        with self.lock:
            if not os.path.exists(p):
                fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as f:
                    f.write(secrets.token_hex(32))
            with open(p) as f:
                return f.read().strip()
