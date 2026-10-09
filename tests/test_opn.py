"""The client for the firewall: certificate pinning (trust on first use), errors with clear causes, the fixed command list."""
import pytest
from app.opn import Opn, OpnError, PinMismatch, check_command

K, S = 'K' * 40, 'S' * 40


def client(fw, store, verify='pin', key=K, secret=S):
    return Opn(fw.url, key, secret, store, verify=verify, timeout=5)


def test_first_contact_pins_the_certificate(fw, store):
    assert store.get_pin() is None
    st = client(fw, store).status()
    assert st['level'] == 'calm' and st['last']['summary']
    assert store.get_pin()['fp'] == fw.fp, 'the SHA-256 of the certificate is remembered'
    assert client(fw, store).status()['level'] == 'calm', 'the same certificate keeps working'


def test_a_changed_certificate_is_refused_and_nothing_is_sent(fw, store):
    c = client(fw, store); c.status()
    n = len(fw.calls)
    fw.rotate_cert()
    with pytest.raises(PinMismatch) as e:
        c.command('analyze')
    assert e.value.kind == 'pin' and e.value.old == fw.fp or e.value.old != e.value.new
    assert len(fw.calls) == n, 'the request must not reach the (possibly impersonated) server'
    assert store.get_pin()['fp'] != fw.fp, 'the old pin stays until the user confirms'


def test_trust_again_after_the_user_confirms(fw, store):
    c = client(fw, store); c.status()
    fw.rotate_cert()
    with pytest.raises(PinMismatch):
        c.status()
    c.trust_now()
    assert store.get_pin()['fp'] == fw.fp and c.status()['level'] == 'calm'


def test_system_verification_refuses_a_self_signed_certificate(fw, store):
    with pytest.raises(OpnError) as e:
        client(fw, store, verify='system').status()
    assert 'Zertifikat' in str(e.value) and store.get_pin() is None


def test_only_https_is_accepted(store):
    with pytest.raises(OpnError):
        Opn('http://192.168.1.1', K, S, store)


@pytest.mark.parametrize('mode,kind,frag', [('403', 'auth', 'Recht'), ('500', 'error', 'HTTP 500'), ('html', 'error', 'kein JSON'), ('drop', 'offline', 'unterbrochen')])
def test_errors_say_what_is_wrong(fw, store, mode, kind, frag):
    fw.mode = mode
    with pytest.raises(OpnError) as e:
        client(fw, store).status()
    assert e.value.kind == kind and frag in str(e.value)
    assert K not in str(e.value) and S not in str(e.value), 'no secret in a message'


def test_wrong_key_is_an_auth_error(fw, store):
    with pytest.raises(OpnError) as e:
        client(fw, store, key='X' * 40).status()
    assert e.value.kind == 'auth'


def test_unreachable_is_offline(store):
    with pytest.raises(OpnError) as e:
        Opn('https://127.0.0.1:1', K, S, store, timeout=2).status()
    assert e.value.kind == 'offline'


def test_commands_reach_the_firewall_as_form_fields(fw, store):
    c = client(fw, store)
    c.command('task', '  Prüfe das Gerät Kamera  ')
    c.command('invnow', '192.168.1.90')
    assert ('POST', 'task', 'Prüfe das Gerät Kamera') in fw.calls and ('POST', 'invnow', '192.168.1.90') in fw.calls


@pytest.mark.parametrize('cmd,val', [('task', ''), ('task', '   '), ('task', 'x' * 1001), ('invnow', '999.1.1.1'), ('invnow', 'abc'), ('invnow', '1.2.3.4; rm -rf'), ('invnow', '1.2.3.4\n'),
                                     ('do', 'iso:1.2.3.4'), ('do', 'rul:../../etc'), ('do', 'dns:evil'), ('do', 'shp:apply;x'), ('do', 'ids:alert:abc'), ('do', 'tsk:x'), ('do', 'tsk:1234567'), ('do', 'ids:sets;x'), ('do', 'ids:off:12345678901'), ('release', 'abc'), ('release', '1234567'), ('release', '1 or 1'),
                                     ('set', 'a_dns'), ('setkey', 'opnsense'), ('noaus2', ''), ('', '')])
def test_bad_input_never_leaves_this_process(fw, store, cmd, val):
    n = len(fw.calls)
    with pytest.raises(OpnError) as e:
        client(fw, store).command(cmd, val)
    assert e.value.kind == 'input' and len(fw.calls) == n


@pytest.mark.parametrize('cmd,val', [('do', 'iso:192.168.1.90:1790912487'), ('do', 'rul:11111111-2222-3333-4444-555555555555'), ('do', 'dns:rdr'), ('do', 'shp:apply'), ('do', 'ids:alert:2010935'), ('do', 'ids:off:1'), ('do', 'ids:sets'), ('do', 'tsk:1'),
                                     ('do', 'pol:aa:bb:cc:00:02:21'), ('do', 'pol:192.168.2.21'), ('dismiss', 'dns:doh'), ('release', '42'), ('invnow', '2001:db8::1'), ('task', 'ä' * 1000)])
def test_valid_input_is_accepted(cmd, val):
    assert check_command(cmd, val) == val.strip()
