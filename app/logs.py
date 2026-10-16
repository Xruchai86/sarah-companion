"""Monitoring over the Analyzer's logs, like the Monitor tab of Palo Alto Panorama / Log View of FortiAnalyzer.

Log types (each a fixed SQL source, columns from a fixed list - nothing from the browser ever becomes SQL text):
  threat    Suricata alerts (and drops)                   eve, type alert/drop
  app       applications: TLS names, HTTP hosts            eve, type tls/http
  traffic   firewall log (filterlog, parsed on arrival)    fw
  system    logins, changes (audit)                        sys
Filters: time range, free text, and field filters (src, dst, port, action, sev, proto, iface, host, rule, program); a value in the table
can be clicked to filter on it. Paging newest first. Summary: events over time, top sources / destinations / signatures / hosts / rules.
CSV with the same filters (spreadsheet formulas neutralised)."""
import csv
import io
import ipaddress
import re
import time

# OPNsense filterlog layout (ref/core scripts/filter/read_log.py, source: opnsense/ports filterlog/files/description.txt)
GENERAL = 'rulenr,subrulenr,anchorname,rid,interface,reason,action,dir,ipversion'.split(',')
V4 = GENERAL + 'tos,ecn,ttl,id,offset,ipflags,protonum,protoname,length,src,dst'.split(',')
V6 = GENERAL + 'class,flow,hoplimit,protoname,protonum,length,src,dst'.split(',')
PORTS = 'srcport,dstport,datalen'.split(',')


def parse_filterlog(msg):
    """-> dict with rid, iface, action, dir, ipv, proto, src, sport, dst, dport, len, or None when it is no filter log line"""
    p = msg.strip().split(',')
    if len(p) < len(GENERAL):
        return None
    r = dict(zip(GENERAL, p))
    if r['action'] not in ('pass', 'block', 'reject', 'match', 'scrub', 'nat', 'rdr', 'binat'):
        return None
    spec = V4 if r['ipversion'] == '4' else V6 if r['ipversion'] == '6' else None
    if spec:
        r.update(zip(spec[len(GENERAL):], p[len(GENERAL):]))
        if r.get('protonum') in ('6', '17'):
            r.update(zip(PORTS, p[len(spec):]))

    def num(k):
        v = r.get(k, '')
        return int(v) if v.isdigit() else None
    return {'rid': r.get('rid', '')[:64], 'iface': r.get('interface', '')[:32], 'action': r['action'], 'dir': r.get('dir', '')[:8], 'ipv': num('ipversion'),
            'proto': (r.get('protoname') or '').lower()[:16], 'src': r.get('src', '')[:45], 'sport': num('srcport'), 'dst': r.get('dst', '')[:45],
            'dport': num('dstport'), 'len': num('length'), 'rulenr': num('rulenr')}


FW_SQL = 'CREATE TABLE IF NOT EXISTS fw (t DOUBLE, rid VARCHAR, iface VARCHAR, action VARCHAR, dir VARCHAR, ipv TINYINT, proto VARCHAR, src VARCHAR, sport INTEGER, dst VARCHAR, dport INTEGER, len INTEGER, rulenr INTEGER, raw VARCHAR)'
FW_COLS = ('t', 'rid', 'iface', 'action', 'dir', 'ipv', 'proto', 'src', 'sport', 'dst', 'dport', 'len', 'rulenr', 'raw')

# per log type: FROM, fixed WHERE, the columns shown, the filterable fields (name -> SQL expression), the text searched by q
TYPES = {
    'threat': {'from': 'eve', 'where': "type IN ('alert', 'drop')",
               'cols': {'t': 't', 'sev': 'sev', 'action': 'action', 'src': 'src', 'sport': 'sport', 'dst': 'dst', 'dport': 'dport', 'proto': 'proto', 'sig': 'sig',
                        'cat': "raw->>'$.alert.category'", 'sid': "TRY_CAST(raw->>'$.alert.signature_id' AS BIGINT)"},
               'text': "COALESCE(sig, '') || ' ' || COALESCE(raw->>'$.alert.category', '')"},
    'app': {'from': 'eve', 'where': "type IN ('tls', 'http')",
            'cols': {'t': 't', 'type': 'type', 'src': 'src', 'dst': 'dst', 'dport': 'dport', 'host': 'host', 'version': "raw->>'$.tls.version'",
                     'ja4': "raw->>'$.tls.ja4'", 'url': "raw->>'$.http.url'", 'agent': "raw->>'$.http.http_user_agent'"},
            'text': "COALESCE(host, '') || ' ' || COALESCE(raw->>'$.http.url', '')"},
    'traffic': {'from': 'fw', 'where': 'TRUE',
                'cols': {'t': 't', 'action': 'action', 'dir': 'dir', 'iface': 'iface', 'proto': 'proto', 'src': 'src', 'sport': 'sport', 'dst': 'dst', 'dport': 'dport',
                         'len': 'len', 'rid': 'rid'},
                'text': "COALESCE(iface, '') || ' ' || COALESCE(rid, '')"},
    'system': {'from': 'sys', 'where': 'TRUE', 'cols': {'t': 't', 'program': 'program', 'msg': 'msg'}, 'text': 'msg'},
}
FIELDS = {'src': 'src', 'dst': 'dst', 'port': None, 'action': 'action', 'sev': 'sev', 'proto': 'proto', 'iface': 'iface', 'host': 'host', 'rid': 'rid', 'program': 'program',
          'sig': 'sig', 'type': 'type', 'dir': 'dir', 'version': None}
TOP = {'threat': [('src', 'src'), ('dst', 'dst'), ('sig', 'sig')], 'app': [('src', 'src'), ('host', 'host'), ('dst', 'dst')],
       'traffic': [('src', 'src'), ('dst', 'dst'), ('dport', 'dport'), ('rid', 'rid')], 'system': [('program', 'program')]}
VALUE = re.compile(r'^[\w.:/@*\- ]{1,200}$', re.UNICODE)
MAX_RANGE = 90 * 86400


class BadQuery(ValueError):
    pass


def where(kind, args, now=None):
    """-> (sql, params) for log type `kind` and the request's filters; raises BadQuery for anything unknown or malformed"""
    if kind not in TYPES:
        raise BadQuery('unbekannte Protokollart')
    T = TYPES[kind]
    now = now or time.time()
    try:
        t1 = float(args.get('to') or now)
        t0 = float(args.get('from') or (t1 - 86400))
    except ValueError:
        raise BadQuery('Zeitraum ungültig')
    if not (0 <= t1 - t0 <= MAX_RANGE):
        raise BadQuery('Zeitraum ungültig (höchstens 90 Tage)')
    sql, par = ['(%s)' % T['where'], 't >= ?', 't < ?'], [t0, t1]
    q = str(args.get('q') or '').strip()
    if q:
        if len(q) > 200:
            raise BadQuery('Suchtext zu lang')
        sql.append('(%s) ILIKE ?' % T['text'])
        par.append('%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
    cols = T['cols']
    for k in FIELDS:
        v = args.get(k)
        if v in (None, ''):
            continue
        v = str(v).strip()
        neg = v.startswith('!')                                          # !value: everything except
        v = v[1:] if neg else v
        if not VALUE.match(v):
            raise BadQuery('Filter %s ungültig' % k)
        if k == 'port':
            if not v.isdigit():
                raise BadQuery('Port ungültig')
            expr = '(%s)' % ' OR '.join('%s = ?' % c for c in ('sport', 'dport') if c in cols)
            if expr == '()':
                raise BadQuery('Diese Protokollart hat keine Ports')
            n = expr.count('?')
            sql.append(('NOT ' if neg else '') + expr)
            par.extend([int(v)] * n)
            continue
        col = cols.get(k) if k in cols else None
        if col is None:
            raise BadQuery('Diese Protokollart kennt kein Feld %s' % k)
        if k in ('src', 'dst') and '/' in v:                            # a network: compare as INET
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError:
                raise BadQuery('Netz ungültig')
            sql.append(('NOT ' if neg else '') + "(TRY_CAST(%s AS INET) <<= ?::INET)" % col)
            par.append(v)
        elif k == 'sev':
            if v not in ('1', '2', '3', '4'):
                raise BadQuery('Schwere 1 bis 4')
            sql.append('%s %s ?' % (col, '!=' if neg else '='))       # sev filters exactly; the summary groups
            par.append(int(v))
        elif '*' in v:
            sql.append('%s %sLIKE ?' % (col, 'NOT ' if neg else ''))
            par.append(v.replace('%', '\\%').replace('_', '\\_').replace('*', '%'))
        else:
            sql.append('COALESCE(CAST(%s AS VARCHAR), \'\') %s ?' % (col, '!=' if neg else '='))
            par.append(v)
    return ' AND '.join(sql), par


class Logs:
    def __init__(self, analyzer):
        self.a = analyzer
        with analyzer.dblock:
            analyzer.con.execute(FW_SQL)

    def _q(self, sql, par):
        with self.a.dblock:
            cur = self.a.con.execute(sql, par)
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r)) for r in cur.fetchall()]

    def search(self, kind, args, now=None):
        w, par = where(kind, args, now)
        T = TYPES[kind]
        try:
            limit = max(1, min(500, int(args.get('limit') or 100)))
            offset = max(0, min(100000, int(args.get('offset') or 0)))
        except ValueError:
            raise BadQuery('Seite ungültig')
        cols = ', '.join('%s AS "%s"' % (e, n) for n, e in T['cols'].items())
        rows = self._q('SELECT %s, rowid AS "id" FROM %s WHERE %s ORDER BY t DESC, rowid DESC LIMIT %d OFFSET %d' % (cols, T['from'], w, limit, offset), par)
        total = self._q('SELECT COUNT(*) AS n FROM %s WHERE %s' % (T['from'], w), par)[0]['n']
        return {'kind': kind, 'rows': rows, 'total': total, 'limit': limit, 'offset': offset, 'cols': list(T['cols'])}

    def detail(self, kind, rid):
        if kind not in TYPES or not str(rid).isdigit():
            raise BadQuery('unbekannter Eintrag')
        T = TYPES[kind]
        raw = {'threat': 'raw', 'app': 'raw', 'traffic': 'raw', 'system': 'msg'}[kind]
        r = self._q('SELECT %s, CAST(%s AS VARCHAR) AS raw FROM %s WHERE rowid = ? AND %s' % (
            ', '.join('%s AS "%s"' % (e, n) for n, e in T['cols'].items()), raw, T['from'], T['where']), [int(rid)])
        if not r:
            raise BadQuery('Eintrag nicht (mehr) vorhanden')
        return r[0]

    def summary(self, kind, args, now=None):
        w, par = where(kind, args, now)
        T = TYPES[kind]
        t0, t1 = par[0], par[1]
        step = max(60, int((t1 - t0) / 48 // 60 * 60) or 60)
        hist = self._q('SELECT CAST(floor(t / %d) * %d AS BIGINT) AS b, COUNT(*) AS n FROM %s WHERE %s GROUP BY 1 ORDER BY 1' % (step, step, T['from'], w), par)
        out = {'kind': kind, 'step': step, 'from': t0, 'to': t1, 'hist': hist, 'top': {}}
        for name, col in TOP[kind]:
            out['top'][name] = self._q('SELECT CAST(%s AS VARCHAR) AS v, COUNT(*) AS n FROM %s WHERE %s AND %s IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10' % (
                T['cols'].get(col, col), T['from'], w, T['cols'].get(col, col)), par)
        if kind in ('threat', 'traffic'):
            out['top']['action'] = self._q('SELECT action AS v, COUNT(*) AS n FROM %s WHERE %s GROUP BY 1 ORDER BY 2 DESC' % (T['from'], w), par)
        if kind == 'threat':
            out['top']['sev'] = self._q('SELECT CAST(sev AS VARCHAR) AS v, COUNT(*) AS n FROM %s WHERE %s GROUP BY 1 ORDER BY 1' % (T['from'], w), par)
        return out

    def csv(self, kind, args, now=None, limit=50000):
        w, par = where(kind, args, now)
        T = TYPES[kind]
        rows = self._q('SELECT %s FROM %s WHERE %s ORDER BY t DESC LIMIT %d' % (', '.join('%s AS "%s"' % (e, n) for n, e in T['cols'].items()), T['from'], w, limit), par)
        buf = io.StringIO()
        wr = csv.writer(buf, delimiter=';', lineterminator='\r\n')
        wr.writerow(list(T['cols']))
        for r in rows:
            wr.writerow([safe_cell(time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(r['t'])) if k == 't' and r[k] else r[k]) for k in T['cols']])
        return '﻿' + buf.getvalue()

    def counts(self, now=None):
        """events per log type in the last 24 hours (the tab badges)"""
        now = now or time.time()
        out = {}
        for k, T in TYPES.items():
            out[k] = self._q('SELECT COUNT(*) AS n FROM %s WHERE (%s) AND t >= ?' % (T['from'], T['where']), [now - 86400])[0]['n']
        return out


def safe_cell(v):
    """a value starting with = + - @ is read as a formula by spreadsheets: prefix it"""
    s = '' if v is None else str(v)
    return "'" + s if s[:1] in ('=', '+', '-', '@', '\t', '\r') else s
