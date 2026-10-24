"""Talks to the S.A.R.A.H. API of the firewall: /api/scdeck/stats/sarah (GET = status, POST cmd=... value=...).

  - Only a FIXED set of commands can be sent, each with the same input rules the firewall applies itself (StatsController::sarahArgs).
    This is not a generic proxy: whatever the browser asks for, nothing else ever reaches the firewall.
  - OPNsense usually has a self-signed certificate. Trust on first use: the first successful connection stores the SHA-256 fingerprint of the
    certificate; every later connection must present the same one (a changed certificate is refused until you trust it again, on purpose).
    With verify="system" the normal certificate check (CA + host name) is used instead.
  - The key and secret never leave this process: they are not logged and never put into an answer.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.parse

PATH = '/api/scdeck/stats/sarah'
PATH_PROTECT = '/api/scdeck/stats/protect'     # read only: status and previews (os-scdeck 0.79 adds it to the app's right)
ID_ACTION = re.compile(r'(iso:[0-9a-fA-F.:]{3,45}:\d{1,12}|rul:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|dns:(rdr|doh|dohcore|dot)|shp:apply|ids:(alert|off):\d{1,10}|ids:sets|hrd:(dnssec|rebind|wan_blockpriv|wan_blockbogons|tlslog|evelimit)|prf:[a-z0-9_]{1,32}:(basis|standard|streng)|dvt:(apply|now|zen)|sup:(basis|standard|streng)|tsk:[0-9]{1,6}|cat:[a-z0-9-]{1,40}|pol:(([0-9a-f]{2}:){5}[0-9a-f]{2}|[0-9a-fA-F.:]{3,45}))')
ID_JOURNAL = re.compile(r'\d{1,6}')
CASE = re.compile(r'(new|progress|done|false):\d{1,12}')
HOSTNAME = re.compile(r'(?=.{1,200}$)([a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?\.)+[a-z0-9-]{2,63}')
NOTE_B64 = re.compile(r'[A-Za-z0-9_-]{1,1400}={0,2}')
ZONE = re.compile(r'[a-z0-9_]{1,32}')
LEVELS = ('basis', 'standard', 'streng')
PSKIP = re.compile(r'none|[a-z0-9_]{1,32}(,[a-z0-9_]{1,32}){0,63}')


class OpnError(Exception):
    """a message that is fit to be shown to the user (German, no secrets)"""

    def __init__(self, msg, kind='error'):
        super().__init__(msg)
        self.kind = kind


class PinMismatch(OpnError):
    def __init__(self, old, new):
        super().__init__('Das Zertifikat der Firewall hat sich geändert. Aus Sicherheitsgründen wird nichts gesendet, bis du es unter „Mehr › Verbindung“ erneut bestätigst.', 'pin')
        self.old, self.new = old, new


def fmt_fp(hexstr):
    h = (hexstr or '').upper()
    return ':'.join(h[i:i + 2] for i in range(0, len(h), 2))


def valid_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def check_command(cmd, value='', key=None):
    """-> value to send, or raises OpnError. Mirrors the firewall's own input rules."""
    value = '' if value is None else str(value)
    if cmd == 'deckset':                                       # the two DECK settings of the protection page (os-scdeck 0.79)
        if not ((key == 'dvtzen' and value in ('on', 'off')) or (key in ('pskip', 'dvtskip') and PSKIP.fullmatch(value))):
            raise OpnError('Ungültige Einstellung.', 'input')
        return value
    if cmd in ('analyze', 'tasks', 'inv', 'noaus', 'incidents', 'rulemap', 'job', 'apps'):
        return ''
    if cmd == 'appdev':
        v = value.strip().lower()
        if not re.fullmatch(r'([0-9a-f]{2}(:[0-9a-f]{2}){5}|[0-9a-f.:]{3,45})', v):
            raise OpnError('Ungültiges Gerät.', 'input')
        return v
    if cmd in ('feed', 'jobdone'):                             # the Analyzer's delivery (8 MB) / a model reply (4 MB): JSON built here
        if len(value) > (8 if cmd == 'feed' else 4) * 1024 * 1024:
            raise OpnError('Lieferung zu groß.', 'input')
        return value
    if cmd == 'inorm':                                        # 1.08: <ip>|<server name> - this name is normal for this device
        ip, _sep, name = value.partition('|')
        if not (3 <= len(ip) <= 45) or not valid_ip(ip):
            raise OpnError('Das ist keine gültige IP-Adresse.', 'input')
        if not HOSTNAME.fullmatch(name.lower()):
            raise OpnError('Ungültiger Name.', 'input')
        return ip + '|' + name.lower()
    if cmd in ('icase', 'inote', 'ihand'):                    # working on an incident: <ip>|<status>:<until> | <ip>|<note, base64url> | <ip>
        ip, sep, rest = value.partition('|')
        if cmd == 'ihand' and sep:
            raise OpnError('Das ist keine gültige IP-Adresse.', 'input')
        if not (3 <= len(ip) <= 45) or not valid_ip(ip):
            raise OpnError('Das ist keine gültige IP-Adresse.', 'input')
        if cmd == 'icase' and not CASE.fullmatch(rest):
            raise OpnError('Ungültiger Status.', 'input')
        if cmd == 'inote' and not NOTE_B64.fullmatch(rest):
            raise OpnError('Die Notiz ist zu lang oder leer.', 'input')
        return ip if cmd == 'ihand' else ip + '|' + rest
    if cmd == 'task':
        t = value.strip()
        if not t or len(t) > 1000:
            raise OpnError('Ein Auftrag braucht 1 bis 1000 Zeichen.', 'input')
        return t
    if cmd == 'invnow':
        if not (3 <= len(value) <= 45) or not re.fullmatch(r'[0-9a-fA-F.:]+', value) or not valid_ip(value):
            raise OpnError('Das ist keine gültige IP-Adresse.', 'input')
        return value
    if cmd in ('do', 'dismiss'):
        if not ID_ACTION.fullmatch(value):
            raise OpnError('Ungültige Kennung.', 'input')
        return value
    if cmd == 'release':
        if not ID_JOURNAL.fullmatch(value):
            raise OpnError('Ungültige Kennung.', 'input')
        return value
    raise OpnError('Unbekannter Befehl.', 'input')


class Opn:
    def __init__(self, url, key, secret, store, verify='pin', timeout=20):
        u = urllib.parse.urlparse(url if '://' in url else 'https://' + url)
        if u.scheme != 'https' or not u.hostname:
            raise OpnError('Die Adresse der Firewall muss mit https:// beginnen.')
        self.host, self.port = u.hostname, u.port or 443
        self.auth = 'Basic ' + base64.b64encode(('%s:%s' % (key, secret)).encode()).decode()
        self.store, self.verify, self.timeout = store, verify, timeout

    # ---------------------------------------------------------------- connection with the certificate check
    def _connect(self, trust_now=False):
        if self.verify == 'system':
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE        # replaced by the fingerprint check right below
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ctx)
        try:
            conn.connect()
        except ssl.SSLCertVerificationError:
            raise OpnError('Das Zertifikat der Firewall ist nicht vertrauenswürdig (Verbindungsart „pin“ erlaubt selbst signierte).')
        except (socket.timeout, TimeoutError):
            raise OpnError('Die Firewall antwortet nicht (Zeitüberschreitung).', 'offline')
        except (OSError, ssl.SSLError) as e:
            raise OpnError('Keine Verbindung zur Firewall (%s).' % (getattr(e, 'strerror', None) or type(e).__name__), 'offline')
        if self.verify != 'system':
            der = conn.sock.getpeercert(binary_form=True)
            fp = hashlib.sha256(der).hexdigest()
            pin = self.store.get_pin()
            if pin is None or trust_now:
                self.store.set_pin(fp)
            elif pin['fp'] != fp:
                conn.close()
                raise PinMismatch(pin['fp'], fp)
        return conn

    def peek_fingerprint(self):
        """what certificate does the firewall show right now (for the 'trust again' step) - nothing is stored"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s, ctx.wrap_socket(s, server_hostname=self.host) as t:
                return hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest()
        except (OSError, ssl.SSLError) as e:
            raise OpnError('Keine Verbindung zur Firewall (%s).' % type(e).__name__, 'offline')

    def trust_now(self):
        self.store.set_pin(self.peek_fingerprint())

    # ---------------------------------------------------------------- requests
    def _request(self, method, form=None, path=PATH):
        conn = self._connect()
        try:
            body, headers = None, {'Authorization': self.auth, 'Accept': 'application/json'}
            if form is not None:
                body = urllib.parse.urlencode(form).encode()
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            try:
                conn.request(method, path, body=body, headers=headers)
                r = conn.getresponse()
                raw = r.read(4_000_000)
            except (socket.timeout, TimeoutError):
                raise OpnError('Die Firewall antwortet nicht (Zeitüberschreitung).', 'offline')
            except (OSError, http.client.HTTPException) as e:
                raise OpnError('Die Verbindung zur Firewall wurde unterbrochen (%s).' % type(e).__name__, 'offline')
        finally:
            conn.close()
        if r.status in (401, 403) and path != PATH:
            raise OpnError('Die Firewall erlaubt der App die Schutz-Übersicht nicht. Das Recht „DECK: S.A.R.A.H. (Apps)“ umfasst sie ab os-scdeck 0.79 - bitte das Plugin aktualisieren.', 'auth')
        if r.status == 404 and path != PATH:
            raise OpnError('Die Schutz-Übersicht gibt es dort nicht. Sie braucht os-scdeck ab 0.79.', 'plugin')
        if r.status in (401, 403):
            raise OpnError('Die Firewall lehnt den Zugang ab. Prüfe Schlüssel und Geheimnis und ob der Benutzer das Recht „DECK: S.A.R.A.H. (Apps)“ hat.', 'auth')
        if r.status == 404:
            raise OpnError('Die Schnittstelle gibt es dort nicht. Ist das Plugin os-scdeck (ab 0.17) installiert?', 'plugin')
        if r.status >= 400:
            raise OpnError('Die Firewall meldet einen Fehler (HTTP %d).' % r.status)
        try:
            data = json.loads(raw.decode('utf-8', 'replace'))
        except ValueError:
            raise OpnError('Die Antwort der Firewall ist kein JSON (falsche Adresse?).')
        return data

    def status(self):
        d = self._request('GET')
        if isinstance(d, dict) and d.get('error'):
            raise OpnError(str(d['error'])[:200])
        return d

    def protect(self, zone=None, level=None, ids=None):
        """the protection overview (zones, Divert, Suricata policies, Unbound lists); with zone+level the preview of a profile, with ids the
        preview of the Suricata policies of a level - read only, the firewall's guards decide when it is applied (sarah cmd=do)"""
        q = ''
        if ids is not None:
            if ids not in LEVELS:
                raise OpnError('Ungültige Stufe.', 'input')
            q = '?ids=' + ids
        elif zone is not None:
            if not ZONE.fullmatch(str(zone)) or level not in LEVELS:
                raise OpnError('Ungültige Zone oder Stufe.', 'input')
            q = '?zone=%s&level=%s' % (zone, level)
        d = self._request('GET', path=PATH_PROTECT + q)
        if not isinstance(d, dict):
            raise OpnError('Die Antwort der Firewall ist unerwartet.')
        return d

    def command(self, cmd, value='', key=None):
        form = {'cmd': cmd}
        v = check_command(cmd, value, key)
        if cmd == 'deckset':
            form['key'] = key
        if v != '':
            form['value'] = v
        d = self._request('POST', form)
        return d
