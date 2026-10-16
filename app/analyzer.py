"""S.A.R.A.H. Analyzer: receives the firewall's logs (syslog-ng of OPNsense, plugin os-scdeck 0.60+) and keeps them in DuckDB,
so the firewall only sends and never evaluates (docs/ANALYZER-ENTWURF.md).

Lines, one per event (written by analyzer.py on the firewall):
  E <eve.json line>                     Suricata: alerts, TLS, HTTP, drops ...
  S <ISO time> <program> <message>      firewall log (filterlog), logins/audit

  receiver   TCP or TLS (own certificate, made here once; the firewall trusts exactly this one - syslog-ng 4.12 checks the certificate,
             not the host name, checked on the test firewall). Only the addresses in ANALYZER_ALLOW may send (default: the firewall).
  queue      fixed size: a burst beyond it is dropped and counted, memory never grows without bound
  writer     batches every 2 s: Suricata lines through DuckDB's own JSON reader (fast), the rest in one insert
  retention  ANALYZER_DAYS (30) and ANALYZER_MAX_GB (20): hourly, the oldest data goes first
Counters (received, written, dropped, bad lines) are shown in the app; the firewall shows its own (sent, waiting, dropped)."""
import datetime
import hashlib
import ipaddress
import logging
import os
import queue
import socket
import socketserver
import ssl
import threading
import time

log = logging.getLogger("sarah.analyzer")
LINE_MAX = 256 * 1024
QUEUE_MAX = 200000
BATCH_SECONDS = 2.0

EVE_SQL = """
INSERT INTO eve SELECT epoch(TRY_CAST(j->>'timestamp' AS TIMESTAMPTZ)), j->>'event_type', j->>'src_ip', TRY_CAST(j->>'src_port' AS INTEGER),
       j->>'dest_ip', TRY_CAST(j->>'dest_port' AS INTEGER), j->>'proto', COALESCE(j->>'$.tls.sni', j->>'$.http.hostname'), j->>'$.alert.signature',
       TRY_CAST(j->>'$.alert.severity' AS TINYINT), j->>'$.alert.action', j
FROM (SELECT json AS j FROM read_json_objects(?, format='newline_delimited', ignore_errors=true)) WHERE j IS NOT NULL"""


def addresses(spec):
    nets = []
    for x in (spec or '').split(','):
        x = x.strip()
        if x:
            try:
                nets.append(ipaddress.ip_network(x, strict=False))
            except ValueError:
                try:
                    for info in socket.getaddrinfo(x, None):
                        nets.append(ipaddress.ip_network(info[4][0]))
                except OSError:
                    log.warning("ANALYZER_ALLOW: %s not resolvable", x)
    return nets


def own_cert(d):
    """a self-made certificate for the receiver (10 years); the firewall pins it. Made once, kept in DATA_DIR/analyzer/tls."""
    cert, key = os.path.join(d, 'cert.pem'), os.path.join(d, 'key.pem')
    if os.path.isfile(cert) and os.path.isfile(key):
        return cert, key
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    os.makedirs(d, exist_ok=True)
    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'S.A.R.A.H. Analyzer')])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(k, hashes.SHA256()))
    with open(key + '.tmp', 'wb') as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(key + '.tmp', 0o600)
    os.replace(key + '.tmp', key)
    with open(cert + '.tmp', 'wb') as f:
        f.write(c.public_bytes(serialization.Encoding.PEM))
    os.replace(cert + '.tmp', cert)
    return cert, key


class Analyzer:
    def __init__(self, data_dir, env, default_allow=''):
        self.dir = os.path.join(data_dir, 'analyzer')
        os.makedirs(self.dir, exist_ok=True)
        self.port = int(env.get('ANALYZER_PORT', '6514') or 0)
        self.tls = env.get('ANALYZER_TLS', 'on') != 'off'
        self.days = max(1, int(env.get('ANALYZER_DAYS', '30') or 30))
        self.max_bytes = int(float(env.get('ANALYZER_MAX_GB', '20') or 20) * 1024 ** 3)
        self.allow = addresses(env.get('ANALYZER_ALLOW') or default_allow)
        self.db_path = os.path.join(self.dir, 'logs.duckdb')
        self.q = queue.Queue(QUEUE_MAX)
        self.c = {'received': 0, 'written': 0, 'dropped_queue': 0, 'dropped_long': 0, 'bad': 0, 'refused': 0, 'connections': 0, 'last': 0, 'senders': {}}
        self.lock = threading.Lock()
        self.dblock = threading.Lock()
        self.stop_ev = threading.Event()
        self.server = None
        import duckdb
        self.con = duckdb.connect(self.db_path)
        self.con.execute("SET threads = %d" % max(1, int(env.get('ANALYZER_THREADS', '2') or 2)))
        self.con.execute("SET memory_limit = '%s'" % (env.get('ANALYZER_MEMORY', '1GB') or '1GB'))
        self.con.execute("""CREATE TABLE IF NOT EXISTS eve (t DOUBLE, type VARCHAR, src VARCHAR, sport INTEGER, dst VARCHAR, dport INTEGER, proto VARCHAR,
                            host VARCHAR, sig VARCHAR, sev TINYINT, action VARCHAR, raw JSON)""")
        self.con.execute("CREATE TABLE IF NOT EXISTS sys (t DOUBLE, program VARCHAR, msg VARCHAR)")
        from .logs import FW_SQL, parse_filterlog
        self.con.execute(FW_SQL)
        self.parse_fw = parse_filterlog
        self.migrate()
        self.cert = own_cert(os.path.join(self.dir, 'tls')) if self.tls else None

    # ------------------------------------------------------------ receiving
    def allowed(self, ip):
        if not self.allow:
            return False                                      # nobody configured: nobody may send
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.allow)

    def put(self, line, sender):
        with self.lock:
            self.c['received'] += 1
            self.c['last'] = int(time.time())
            self.c['senders'][sender] = self.c['senders'].get(sender, 0) + 1
        try:
            self.q.put_nowait(line)
        except queue.Full:
            with self.lock:
                self.c['dropped_queue'] += 1

    def handler(self):
        outer = self

        class H(socketserver.StreamRequestHandler):
            timeout = 600

            def handle(self):
                ip = self.client_address[0]
                if not outer.allowed(ip):
                    with outer.lock:
                        outer.c['refused'] += 1
                    return
                with outer.lock:
                    outer.c['connections'] += 1
                conn = self.connection
                if outer.tls:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.load_cert_chain(*outer.cert)
                    ctx.num_tickets = 0                       # no session tickets: a sender that never reads them gets no reset on close
                    try:
                        conn = ctx.wrap_socket(conn, server_side=True)
                    except (ssl.SSLError, OSError):
                        return
                try:
                    outer.read_lines(conn.makefile('rb'), ip)
                except (OSError, ssl.SSLError):
                    pass                                      # the sender went away: what arrived is kept
        return H

    def read_lines(self, f, ip):
        while not self.stop_ev.is_set():
            line = f.readline(LINE_MAX + 1)
            if not line:
                break
            if len(line) > LINE_MAX and not line.endswith(b'\n'):
                with self.lock:
                    self.c['dropped_long'] += 1
                while line and not line.endswith(b'\n'):      # skip the rest of the overlong line
                    line = f.readline(LINE_MAX + 1)
                continue
            self.put(line.rstrip(b'\r\n'), ip)

    def start(self):
        threading.Thread(target=self.writer, daemon=True, name='analyzer-writer').start()
        if not self.port:
            return
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        socketserver.ThreadingTCPServer.daemon_threads = True
        self.server = socketserver.ThreadingTCPServer(('0.0.0.0', self.port), self.handler())
        threading.Thread(target=self.server.serve_forever, daemon=True, name='analyzer-recv').start()
        log.info("analyzer listening on %d (%s), allowed: %s", self.port, 'TLS' if self.tls else 'TCP', ', '.join(map(str, self.allow)) or 'nobody')

    def stop(self):
        self.stop_ev.set()
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    # ------------------------------------------------------------ writing
    def flush(self, lines):
        eve, sysrows, fwrows, bad = [], [], [], 0
        for raw in lines:
            if raw.startswith(b'E '):
                eve.append(raw[2:])
            elif raw.startswith(b'S '):
                p = raw[2:].decode('utf-8', 'replace').split(' ', 2)
                if len(p) == 3:
                    try:
                        t = datetime.datetime.fromisoformat(p[0]).timestamp()
                    except ValueError:
                        t = time.time()
                    f = self.parse_fw(p[2]) if p[1] == 'filterlog' else None
                    if f:
                        fwrows.append((t, f['rid'], f['iface'], f['action'], f['dir'], f['ipv'], f['proto'], f['src'], f['sport'], f['dst'], f['dport'], f['len'], f['rulenr'], p[2][:2000]))
                    else:
                        sysrows.append((t, p[1][:64], p[2][:4000]))
                else:
                    bad += 1
            else:
                bad += 1
        written = 0
        with self.dblock:
            if eve:
                path = os.path.join(self.dir, 'batch.ndjson')
                with open(path, 'wb') as f:
                    f.write(b'\n'.join(eve) + b'\n')
                before = self.con.execute('SELECT COUNT(*) FROM eve').fetchone()[0]
                self.con.execute(EVE_SQL, [path])
                n = self.con.execute('SELECT COUNT(*) FROM eve').fetchone()[0] - before
                written += n
                bad += len(eve) - n
                os.remove(path)
            if sysrows:
                self.con.executemany('INSERT INTO sys VALUES (?, ?, ?)', sysrows)
                written += len(sysrows)
            if fwrows:
                self.con.executemany('INSERT INTO fw VALUES (%s)' % ', '.join('?' * 14), fwrows)
                written += len(fwrows)
        with self.lock:
            self.c['written'] += written
            self.c['bad'] += bad

    def writer(self):
        last_clean = 0
        while not self.stop_ev.is_set():
            lines, end = [], time.time() + BATCH_SECONDS
            while time.time() < end and len(lines) < 50000:
                try:
                    lines.append(self.q.get(timeout=max(0.05, end - time.time())))
                except queue.Empty:
                    pass
            if lines:
                try:
                    self.flush(lines)
                except Exception:
                    log.exception("analyzer: batch not written")
                    with self.lock:
                        self.c['bad'] += len(lines)
            if time.time() - last_clean > 3600:
                last_clean = time.time()
                try:
                    self.clean()
                except Exception:
                    log.exception("analyzer: clean-up failed")

    def clean(self, now=None):
        """retention: older than ANALYZER_DAYS goes; above ANALYZER_MAX_GB the oldest day goes until it fits (DuckDB reuses the freed space)"""
        now = now or time.time()
        with self.dblock:
            for tb in ('eve', 'sys', 'fw'):
                self.con.execute('DELETE FROM %s WHERE t < ?' % tb, [now - self.days * 86400])
            for _ in range(self.days):
                if self.size() <= self.max_bytes:
                    break
                oldest = self.con.execute('SELECT MIN(t) FROM (SELECT MIN(t) AS t FROM eve UNION ALL SELECT MIN(t) FROM sys UNION ALL SELECT MIN(t) FROM fw)').fetchone()[0]
                if oldest is None:
                    break
                for tb in ('eve', 'sys', 'fw'):
                    self.con.execute('DELETE FROM %s WHERE t < ?' % tb, [oldest + 86400])
                self.con.execute('CHECKPOINT')
                if self.size() > self.max_bytes and self.con.execute('SELECT COUNT(*) FROM eve').fetchone()[0] == 0:
                    break
            self.con.execute('CHECKPOINT')

    def migrate(self):
        """firewall log lines kept as plain text by 1.2.0 are parsed into the table fw (once)"""
        rows = self.con.execute("SELECT rowid, t, msg FROM sys WHERE program = 'filterlog'").fetchall()
        out = []
        for _, t, msg in rows:
            f = self.parse_fw(msg)
            if f:
                out.append((t, f['rid'], f['iface'], f['action'], f['dir'], f['ipv'], f['proto'], f['src'], f['sport'], f['dst'], f['dport'], f['len'], f['rulenr'], msg[:2000]))
        if out:
            self.con.executemany('INSERT INTO fw VALUES (%s)' % ', '.join('?' * 14), out)
        if rows:
            self.con.execute("DELETE FROM sys WHERE program = 'filterlog'")

    def size(self):
        return sum(os.path.getsize(p) for p in (self.db_path, self.db_path + '.wal') if os.path.exists(p))

    # ------------------------------------------------------------ for the app
    def cert_pem(self):
        if not self.cert:
            return ''
        with open(self.cert[0]) as f:
            return f.read()

    def status(self):
        with self.lock:
            c = dict(self.c, senders=dict(self.c['senders']))
        with self.dblock:
            rows = {tb: self.con.execute('SELECT COUNT(*), MIN(t), MAX(t) FROM %s' % tb).fetchone() for tb in ('eve', 'sys', 'fw')}
        pem = self.cert_pem()
        return {'port': self.port, 'tls': self.tls, 'allow': [str(n) for n in self.allow], 'days': self.days, 'max_gb': round(self.max_bytes / 1024 ** 3, 1),
                'bytes': self.size(), 'queue': self.q.qsize(), 'counters': c,
                'tables': {tb: {'rows': r[0], 'first': int(r[1]) if r[1] else None, 'last': int(r[2]) if r[2] else None} for tb, r in rows.items()},
                'cert': pem, 'cert_sha256': hashlib.sha256(pem.encode()).hexdigest() if pem else ''}
