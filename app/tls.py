"""HTTPS with the certificate your OPNsense renews by ACME.

OPNsense's ACME plugin ("Services > ACME Client > Automations > Upload certificate via SFTP") puts after every renewal
    <remote path>/<name>/cert.pem, key.pem, ca.pem, fullchain.pem
(file names and rights as in its upload_sftp.php). Point it at this container's data folder (.../tls). Here:
  - the pair is looked for in TLS_DIR or one folder below it (fullchain.pem, else cert.pem, with key.pem); the newest wins
  - a pair is only used after it passed the check: key matches the certificate, already valid and not expired
  - a renewed pair is loaded into the RUNNING TLS context (new connections get it, no restart); a broken or half uploaded pair never
    replaces a working one - the old one stays and the error is shown
  - no pair: plain HTTP as before; the first pair that appears switches the server to HTTPS (one in-process restart)
The private key is never logged or shown."""
import datetime
import hashlib
import logging
import os
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import serialization

log = logging.getLogger("sarah.tls")
CHECK_EVERY = int(os.environ.get("TLS_CHECK_SECONDS", "60"))


def tls_dir():
    return os.environ.get("TLS_DIR") or os.path.join(os.environ.get("DATA_DIR", "/data"), "tls")


def find_pair(d=None):
    """(cert path, key path) of the newest complete pair in d or one folder below, or None"""
    d = d or tls_dir()
    found = []
    for folder in [d] + sorted(os.path.join(d, x) for x in (os.listdir(d) if os.path.isdir(d) else []) if os.path.isdir(os.path.join(d, x))):
        key = os.path.join(folder, "key.pem")
        cert = next((os.path.join(folder, n) for n in ("fullchain.pem", "cert.pem") if os.path.isfile(os.path.join(folder, n))), None)
        if cert and os.path.isfile(key):
            found.append((max(os.path.getmtime(cert), os.path.getmtime(key)), cert, key))
    return (found and max(found)[1:]) or None


def fingerprint(pair):
    h = hashlib.sha256()
    for p in pair:
        with open(p, "rb") as f:
            h.update(f.read())
    return h.hexdigest()


def inspect(cert_path, key_path, now=None):
    """check a pair before it is used; returns facts for the status, raises ValueError with the reason"""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        with open(cert_path, "rb") as f:
            certs = x509.load_pem_x509_certificates(f.read())
    except Exception:
        raise ValueError("Zertifikat ist kein gültiges PEM")
    try:
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception:
        raise ValueError("Schlüssel ist kein gültiges PEM (oder mit Passwort geschützt)")
    leaf = certs[0]
    raw = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if raw(leaf.public_key()) != raw(key.public_key()):
        raise ValueError("Schlüssel passt nicht zum Zertifikat")
    if now < leaf.not_valid_before_utc:
        raise ValueError("Zertifikat ist noch nicht gültig")
    if now >= leaf.not_valid_after_utc:
        raise ValueError("Zertifikat ist abgelaufen (%s)" % leaf.not_valid_after_utc.date())
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    cn = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    issuer = leaf.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return {"names": names or [a.value for a in cn], "issuer": issuer[0].value if issuer else "", "chain": len(certs),
            "valid_to": leaf.not_valid_after_utc.isoformat(), "days_left": (leaf.not_valid_after_utc - now).days}


def make_context(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


class Tls:
    """what the server serves, and the watcher that keeps it current"""

    def __init__(self):
        self.lock = threading.Lock()
        self.context = None
        self.fp = None
        self.pair = None
        self.status = {"on": False, "dir": tls_dir(), "error": "", "checked": None}
        self.restart = threading.Event()             # set when the first certificate appears while serving plain HTTP

    def initial(self):
        """at start: a checked pair -> TLS context, else None (plain HTTP)"""
        self.check_once()
        return self.context

    def check_once(self, now=None):
        pair = find_pair(self.status["dir"])
        with self.lock:
            self.status["checked"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if not pair:
                if not self.context:
                    self.status.update(on=False, error="")
                return False
            try:
                fp = fingerprint(pair)
            except OSError as e:
                self.status["error"] = "nicht lesbar: %s (Rechte: der Container läuft als Benutzer 99/Gruppe 100)" % e.strerror
                return False
            if fp == self.fp:
                return False
            try:
                info = inspect(*pair, now=now)
                if self.context is None:
                    self.context = make_context(*pair)
                    first = True
                else:
                    make_context(*pair)                    # proves it loads before the running context is touched
                    self.context.load_cert_chain(*pair)  # renewed: new connections get it, nothing restarts
                    first = False
            except (ValueError, ssl.SSLError, OSError) as e:
                self.status["error"] = "Neues Zertifikat nicht übernommen: %s" % (e if isinstance(e, ValueError) else type(e).__name__)
                log.warning("TLS: %s", self.status["error"])
                return False
            self.fp, self.pair = fp, pair
            self.status.update(info, on=True, error="", file=os.path.relpath(pair[0], self.status["dir"]))
            log.info("TLS: %s for %s, valid until %s", "loaded" if first else "renewed", ", ".join(info["names"]), info["valid_to"][:10])
            return first

    def watch(self, stop):
        while not stop.wait(CHECK_EVERY):
            try:
                if self.check_once() and self.context is not None:
                    self.restart.set()                    # plain HTTP until now: switch to HTTPS
            except Exception as e:                        # a watcher that dies would silently freeze the certificate
                log.warning("TLS check failed: %s", e)

    def public(self):
        with self.lock:
            return {k: v for k, v in self.status.items() if k != "dir"}


TLS = Tls()
