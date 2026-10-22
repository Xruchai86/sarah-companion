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
                        'cat': 'cat', 'sid': 'sid'},
               'text': "COALESCE(sig, '') || ' ' || COALESCE(cat, '')"},
    'app': {'from': 'eve', 'where': "type IN ('tls', 'http')",
            'cols': {'t': 't', 'type': 'type', 'src': 'src', 'dst': 'dst', 'dport': 'dport', 'host': 'host', 'version': 'tls_ver',
                     'ja4': 'ja4', 'url': 'url', 'agent': 'agent'},
            'text': "COALESCE(host, '') || ' ' || COALESCE(url, '')"},
    'traffic': {'from': 'fw', 'where': 'TRUE',
                'cols': {'t': 't', 'action': 'action', 'dir': 'dir', 'iface': 'iface', 'proto': 'proto', 'src': 'src', 'sport': 'sport', 'dst': 'dst', 'dport': 'dport',
                         'len': 'len', 'rid': 'rid'},
                'text': "COALESCE(iface, '') || ' ' || COALESCE(rid, '')"},
    'system': {'from': 'sys', 'where': 'TRUE', 'cols': {'t': 't', 'program': 'program', 'msg': 'msg'}, 'text': 'msg'},
}
# the same views over the hourly values (analyzer.py rollup): only the fields a condensed hour still has; COUNT means SUM(n)
TYPES_H = {
    'threat': {'from': 'eve_h', 'where': "type IN ('alert', 'drop')",
               'cols': {'t': 'h', 'sev': 'sev', 'action': 'action', 'src': 'src', 'dst': 'dst', 'dport': 'dport', 'sig': 'sig', 'cat': 'cat'},
               'text': "COALESCE(sig, '') || ' ' || COALESCE(cat, '')"},
    'app': {'from': 'eve_h', 'where': "type IN ('tls', 'http')",
            'cols': {'t': 'h', 'type': 'type', 'src': 'src', 'dst': 'dst', 'dport': 'dport', 'host': 'host'}, 'text': "COALESCE(host, '')"},
    'traffic': {'from': 'fw_h', 'where': 'TRUE',
                'cols': {'t': 'h', 'action': 'action', 'dir': 'dir', 'iface': 'iface', 'proto': 'proto', 'src': 'src', 'dst': 'dst', 'dport': 'dport', 'rid': 'rid'},
                'text': "COALESCE(iface, '') || ' ' || COALESCE(rid, '')"},
}
MAX_RANGE_H = 400 * 86400
FIELDS = {'src': 'src', 'dst': 'dst', 'port': None, 'action': 'action', 'sev': 'sev', 'proto': 'proto', 'iface': 'iface', 'host': 'host', 'rid': 'rid', 'program': 'program',
          'sig': 'sig', 'type': 'type', 'dir': 'dir', 'version': None}
TOP = {'threat': [('src', 'src'), ('dst', 'dst'), ('sig', 'sig')], 'app': [('src', 'src'), ('host', 'host'), ('dst', 'dst')],
       'traffic': [('src', 'src'), ('dst', 'dst'), ('dport', 'dport'), ('rid', 'rid')], 'system': [('program', 'program')]}
VALUE = re.compile(r'^[\w.:/@*\- ]{1,200}$', re.UNICODE)
MAX_RANGE = 90 * 86400


class BadQuery(ValueError):
    pass


def where(kind, args, now=None, types=None, max_range=MAX_RANGE):
    """-> (sql, params) for log type `kind` and the request's filters; raises BadQuery for anything unknown or malformed.
    types=TYPES_H: the same over the hourly values (filters they cannot answer raise BadQuery)"""
    types = types or TYPES
    if kind not in types:
        raise BadQuery('unbekannte Protokollart')
    T = types[kind]
    now = now or time.time()
    try:
        t1 = float(args.get('to') or now)
        t0 = float(args.get('from') or (t1 - 86400))
    except ValueError:
        raise BadQuery('Zeitraum ungültig')
    if not (0 <= t1 - t0 <= max_range):
        raise BadQuery('Zeitraum ungültig (höchstens %d Tage)' % (max_range // 86400))
    tc = T['cols'].get('t', 't')
    sql, par = ['(%s)' % T['where'], '%s >= ?' % tc, '%s < ?' % tc], [t0, t1]
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
        clamped = False
        try:                                                             # a longer span (1 year overview): the list shows the last 90 days
            t1 = float(args.get('to') or now or time.time())
            if args.get('from') and t1 - float(args['from']) > MAX_RANGE and t1 - float(args['from']) <= MAX_RANGE_H:
                args, clamped = dict(args, **{'from': t1 - MAX_RANGE}), True
        except ValueError:
            pass
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
        return {'kind': kind, 'rows': rows, 'total': total, 'limit': limit, 'offset': offset, 'cols': list(T['cols']), 'clamped': clamped}

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

    def _parts(self, kind, args, now):
        """the sources of a summary: [(sql FROM ... WHERE ..., params, count expression, time column)]. Within the single rows'
        time span the single rows (exact); before it the hourly values - when every filter of the request exists there.
        -> (parts, t0, t1, note)"""
        now = now or time.time()
        try:
            t1 = float(args.get('to') or now)
            t0 = float(args.get('from') or (t1 - 86400))
        except ValueError:
            raise BadQuery('Zeitraum ungültig')
        T = TYPES[kind]
        first = self._q('SELECT MIN(t) AS m FROM %s WHERE %s' % (T['from'], T['where']), [])[0]['m']
        if first is None:
            cut = t1                                                     # no single rows (left): everything from the hourly values
        else:
            hf = float(int(first // 3600) * 3600)                        # the hour of the oldest single row may be partly deleted:
            src = {'eve': 'eve', 'fw': 'fw'}.get(T['from'])              # from the hourly values only when that hour is condensed already
            up = self._q('SELECT upto AS u FROM rollup WHERE name = ?', [src])[0]['u'] if kind in TYPES_H and self._q('SELECT COUNT(*) AS n FROM rollup WHERE name = ?', [src])[0]['n'] else None
            cut = hf + 3600 if up is not None and up >= hf + 3600 else hf
        cut = max(t0, min(cut, t1))
        parts, note = [], ''
        if kind in TYPES_H and t0 < cut:
            try:
                if args.get('port') or args.get('q'):
                    raise BadQuery('port/q')
                wh, ph = where(kind, dict(args, **{'from': t0, 'to': min(cut, t1)}), now, TYPES_H, MAX_RANGE_H)
                parts.append(('%s WHERE %s' % (TYPES_H[kind]['from'], wh), ph, 'SUM(n)', 'h', TYPES_H[kind]['cols']))
            except BadQuery:
                note = 'Vor %s nur Einzelzeilen: dieser Filter ist in den Stundenwerten nicht enthalten.' % time.strftime('%d.%m.%Y', time.localtime(cut))
        elif t0 < cut and kind not in TYPES_H:
            note = ''
        if t1 > cut:
            w, par = where(kind, dict(args, **{'from': max(t0, cut) if parts else t0, 'to': t1}), now, TYPES, MAX_RANGE_H)
            parts.append(('%s WHERE %s' % (T['from'], w), par, 'COUNT(*)', 't', T['cols']))
        return parts, t0, t1, note

    def summary(self, kind, args, now=None):
        if kind not in TYPES:
            raise BadQuery('unbekannte Protokollart')
        parts, t0, t1, note = self._parts(kind, args, now)
        if t1 - t0 > (MAX_RANGE_H if kind in TYPES_H else MAX_RANGE) or t1 < t0:
            raise BadQuery('Zeitraum ungültig')
        step = max(60, int((t1 - t0) / 48 // 60 * 60) or 60)
        if t1 - t0 > 2 * 86400:
            step = max(step, 3600)                                   # the hourly values have no finer grain

        def union(sel, extra=''):
            q, par = [], []
            for frm, p, cnt, tc, cols in parts:
                q.append('SELECT %s, %s AS n FROM %s %s GROUP BY ALL' % (sel(tc, cols), cnt, frm, extra(cols) if callable(extra) else extra))
                par += p
            return ' UNION ALL '.join(q), par
        sub, par = union(lambda tc, cols: 'CAST(floor(%s / %d) * %d AS BIGINT) AS b' % (tc, step, step))
        hist = self._q('SELECT b, CAST(SUM(n) AS BIGINT) AS n FROM (%s) GROUP BY 1 ORDER BY 1' % sub, par) if parts else []
        out = {'kind': kind, 'step': step, 'from': t0, 'to': t1, 'hist': hist, 'top': {}, 'note': note,
               'hourly': any(tc == 'h' for _f, _p, _c, tc, _cols in parts)}
        for name, col in TOP[kind] + ([('action', 'action')] if kind in ('threat', 'traffic') else []) + ([('sev', 'sev')] if kind == 'threat' else []):
            sub, par = union(lambda tc, cols: 'CAST(%s AS VARCHAR) AS v' % cols.get(col, col), lambda cols: 'AND %s IS NOT NULL' % cols.get(col, col))
            order = 'ORDER BY 1' if name == 'sev' else 'ORDER BY 2 DESC, 1 LIMIT 10' if name not in ('action',) else 'ORDER BY 2 DESC'
            out['top'][name] = self._q('SELECT v, CAST(SUM(n) AS BIGINT) AS n FROM (%s) GROUP BY 1 %s' % (sub, order), par) if parts else []
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
