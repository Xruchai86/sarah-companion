"""Analyzer mode: what the DECK on the firewall needs from Suricata's eve.json, delivered once a minute (os-scdeck feed.py, 0.62+),
so the firewall no longer parses every line of eve.json itself.

  collect   after each stored batch the Analyzer pulls the few records the DECK uses out of the same batch file (DuckDB's JSON reader):
            tls/http (name, version, fingerprint) and alerts
  sum up    records of an inside device with the same name, version and fingerprint become one record with a count ('_n');
            records of the firewall's own WAN address stay per connection - the firewall maps them to the inside device with pf's NAT table
  deliver   every 60 s through the fixed S.A.R.A.H. command `feed`; also when nothing happened (the firewall then knows the Analyzer is there).
            Only while lines arrive: if syslog-ng stops sending, nothing is delivered and the firewall reads eve.json itself again after 10 min.
Buffers have fixed sizes; what does not fit is counted, never kept."""
import collections
import ipaddress
import json
import logging
import threading
import time

log = logging.getLogger("sarah.feeder")
EVERY = 60
MAX_TH = 20000                  # per delivery, the firewall takes at most this many (feed.py MAX_RECORDS)
MAX_AL = 5000
BUF = 200000

PICK_SQL = """
SELECT j->>'timestamp', j->>'event_type', j->>'src_ip', TRY_CAST(j->>'src_port' AS INTEGER), j->>'dest_ip', TRY_CAST(j->>'dest_port' AS INTEGER), j->>'proto',
       j->>'$.tls.sni', j->>'$.tls.version', j->>'$.tls.ja4', j->>'$.tls.ja3.hash', j->>'$.http.hostname',
       j->>'$.alert.signature', TRY_CAST(j->>'$.alert.signature_id' AS BIGINT), TRY_CAST(j->>'$.alert.severity' AS INTEGER), j->>'$.alert.action', j->>'$.alert.category'
FROM (SELECT json AS j FROM read_json_objects(?, format='newline_delimited', ignore_errors=true))
WHERE j->>'event_type' IN ('tls', 'http', 'alert')"""


def inside(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not a.is_loopback or a in ipaddress.ip_network('100.64.0.0/10')


class Feeder:
    def __init__(self):
        self.th = collections.deque(maxlen=BUF)
        self.al = collections.deque(maxlen=BUF)
        self.lock = threading.Lock()
        self.tls_any = False
        self.own = None                 # the firewall's own addresses (from its answer); until known, nothing is summed up
        self.c = {'delivered': 0, 'records': 0, 'failed': 0, 'dropped': 0, 'last': 0, 'error': None}

    def pick(self, con, path):
        """called by the Analyzer under its DB lock right after a batch file was stored"""
        rows = con.execute(PICK_SQL, [path]).fetchall()
        with self.lock:
            for (ts, et, src, sp, dst, dp, proto, sni, ver, ja4, ja3, hh, sig, sid, sev, act, cat) in rows:
                if et == 'alert':
                    if len(self.al) == self.al.maxlen:
                        self.c['dropped'] += 1
                    self.al.append({'timestamp': ts, 'event_type': 'alert', 'src_ip': src, 'src_port': sp, 'dest_ip': dst, 'dest_port': dp, 'proto': proto,
                                    'alert': {'signature': sig, 'signature_id': sid, 'severity': sev, 'action': act, 'category': cat}})
                    continue
                if et == 'tls':
                    self.tls_any = True
                if len(self.th) == self.th.maxlen:
                    self.c['dropped'] += 1
                self.th.append((ts, et, src, sp, dst, dp, proto, sni, ver, ja4, ja3, hh))

    def payload(self, now=None):
        """-> the delivery of everything collected since the last one (the buffers are emptied)"""
        with self.lock:
            th, al, tls_any = list(self.th), list(self.al), self.tls_any
            self.th.clear(); self.al.clear(); self.tls_any = False
        groups = collections.OrderedDict()
        for ts, et, src, sp, dst, dp, proto, sni, ver, ja4, ja3, hh in th:
            device = self.own is not None and src not in self.own and inside(src)
            key = (src, et, sni, ver, ja4, ja3, hh) if device else (src, et, sni, ver, ja4, ja3, hh, sp, dst, dp, proto)
            g = groups.get(key)
            if g:
                g['_n'] += 1
                g['timestamp'] = max(g['timestamp'] or '', ts or '')
                continue
            r = {'timestamp': ts, 'event_type': et, 'src_ip': src, 'src_port': sp, 'dest_ip': dst, 'dest_port': dp, 'proto': proto, '_n': 1}
            if et == 'tls':
                r['tls'] = {k: v for k, v in (('sni', sni), ('version', ver), ('ja4', ja4)) if v}
                if ja3:
                    r['tls']['ja3'] = {'hash': ja3}
            else:
                r['http'] = {'hostname': hh} if hh else {}
            groups[key] = r
        recs = list(groups.values())
        recs.sort(key=lambda r: not inside(r['src_ip']))                 # inside devices first if the limit bites
        if len(recs) > MAX_TH or len(al) > MAX_AL:
            self.c['dropped'] += max(0, len(recs) - MAX_TH) + max(0, len(al) - MAX_AL)
        return {'tls_http': recs[:MAX_TH], 'alerts': al[-MAX_AL:], 'tls_any': tls_any, 'until': int(now or time.time())}

    def deliver(self, opn, receiving):
        """one delivery; `receiving`: lines arrived lately (else the firewall must read eve.json itself - nothing is sent)"""
        if not receiving:
            self.payload()                                               # nothing of a broken stream piles up
            return False
        p = self.payload()
        try:
            r = opn.command('feed', json.dumps(p, separators=(',', ':')))
            if isinstance(r, dict) and r.get('error'):
                raise RuntimeError(str(r['error'])[:200])
            if isinstance(r, dict) and isinstance(r.get('own'), list):
                self.own = set(str(x) for x in r['own'][:64])
            self.c.update(delivered=self.c['delivered'] + 1, records=self.c['records'] + len(p['tls_http']) + len(p['alerts']), last=int(time.time()), error=None)
            return True
        except Exception as e:                                           # the firewall reads eve.json itself after 10 min without a delivery
            self.c.update(failed=self.c['failed'] + 1, error=str(e)[:200])
            log.warning("feed: %s", e)
            return False

    def run(self, opn, analyzer, stop):
        while not stop.wait(EVERY):
            self.deliver(opn, 0 <= time.time() - analyzer.c.get('last', 0) < 600)
