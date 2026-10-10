"""HTTPS with the certificate the OPNsense ACME client uploads by SFTP: found, checked, served, renewed without a restart, a broken upload
never replaces a working certificate, and the first certificate switches a running HTTP server to HTTPS. Real TLS, real server."""
import datetime, os, socket, ssl, threading, time, urllib.request
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from app import tls as T

NOW = datetime.datetime.now(datetime.timezone.utc)


def pem_pair(cn, days=90, start=-1, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test R11")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW + datetime.timedelta(days=start)).not_valid_after(NOW + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False).sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def put(folder, cert, key, name="fullchain.pem"):
    os.makedirs(folder, exist_ok=True)
    open(os.path.join(folder, name), "wb").write(cert)
    open(os.path.join(folder, "key.pem"), "wb").write(key)
    later = time.time() + 2
    for f in (name, "key.pem"):
        os.utime(os.path.join(folder, f), (later, later))


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def peer_cn(port):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s, ctx.wrap_socket(s) as t:
        c = x509.load_der_x509_certificate(t.getpeercert(binary_form=True))
    return c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value


def tiny(env, start):
    start("200 OK", [("Content-Type", "text/plain")]); return [b"ok"]


def test_finds_the_pair_where_the_acme_client_puts_it(tmp_path):
    assert T.find_pair(str(tmp_path)) is None
    c, k = pem_pair("sarah.example.org")
    put(str(tmp_path / "sarah.example.org"), c, k)                     # <remote path>/<name>/fullchain.pem + key.pem
    assert T.find_pair(str(tmp_path))[0].endswith("sarah.example.org/fullchain.pem")
    put(str(tmp_path / "older"), c, k, "cert.pem")
    os.utime(tmp_path / "older" / "cert.pem", (1, 1)); os.utime(tmp_path / "older" / "key.pem", (1, 1))
    assert "sarah.example.org" in T.find_pair(str(tmp_path))[0], "the newest pair wins"


@pytest.mark.parametrize("case,expect", [("ok", None), ("mismatch", "passt nicht"), ("expired", "abgelaufen"), ("future", "noch nicht gültig"), ("garbage", "kein gültiges PEM")])
def test_checks_before_use(tmp_path, case, expect):
    c, k = pem_pair("a.test", days=-1 if case == "expired" else 30, start=-10 if case == "expired" else (5 if case == "future" else -1))
    if case == "mismatch":
        k = pem_pair("other.test")[1]
    if case == "garbage":
        c = b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"
    put(str(tmp_path), c, k)
    if expect is None:
        info = T.inspect(*T.find_pair(str(tmp_path)))
        assert info["names"] == ["a.test"] and info["issuer"] == "Test R11" and 28 <= info["days_left"] <= 30
    else:
        with pytest.raises(ValueError, match=expect):
            T.inspect(*T.find_pair(str(tmp_path)))


def test_served_renewed_live_and_a_broken_upload_changes_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("TLS_DIR", str(tmp_path))
    put(str(tmp_path / "n"), *pem_pair("a.test"))
    t = T.Tls(); assert t.initial() is not None and t.public()["on"]
    import app.__main__ as M
    monkeypatch.setattr(M, "TLS", t)
    port = free_port(); srv = M.build(tiny, port); srv.bind_addr = ("127.0.0.1", port)
    threading.Thread(target=srv.safe_start, daemon=True).start(); time.sleep(0.8)
    try:
        assert peer_cn(port) == "a.test"
        put(str(tmp_path / "n"), *pem_pair("b.test"))
        assert t.check_once() is False                                   # a renewal, not a switch
        assert peer_cn(port) == "b.test", "new connections get the renewed certificate - no restart"
        c, _ = pem_pair("c.test"); put(str(tmp_path / "n"), c, pem_pair("x.test")[1])
        t.check_once()
        assert peer_cn(port) == "b.test" and "passt nicht" in t.public()["error"], "a broken upload never replaces a working certificate"
        assert "BEGIN" not in str(t.public()), "the key is never shown"
    finally:
        srv.stop()


def test_first_certificate_switches_a_running_http_server_to_https(tmp_path, monkeypatch):
    monkeypatch.setenv("TLS_DIR", str(tmp_path))
    import app.__main__ as M
    t = T.Tls(); monkeypatch.setattr(M, "TLS", t); monkeypatch.setattr(T, "CHECK_EVERY", 1)
    port = free_port()
    threading.Thread(target=M.serve, args=(tiny, port), daemon=True).start(); time.sleep(0.8)
    assert urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=5).read() == b"ok", "no certificate: plain HTTP as before"
    put(str(tmp_path / "sarah.test"), *pem_pair("sarah.test"))
    for _ in range(40):
        time.sleep(0.25)
        try:
            if peer_cn(port) == "sarah.test":
                break
        except (ssl.SSLError, OSError):
            pass
    assert peer_cn(port) == "sarah.test", "the first certificate switched the running server to HTTPS"
