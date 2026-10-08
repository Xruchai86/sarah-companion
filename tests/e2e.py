#!/usr/bin/env python3
"""End-to-end test in a real browser (Chromium via Playwright) against the real server and the stand-in firewall.
Needs tests/devserver.py running (it prints its two ports on the first line of the log passed as argv[1])."""
import json, os, sys, time, urllib.request
from playwright.sync_api import sync_playwright

LOG = sys.argv[1] if len(sys.argv) > 1 else '/tmp/devserver.log'
PORTS = json.loads(open(LOG).readline())
BASE, CTL = 'http://127.0.0.1:%d' % PORTS['app'], 'http://127.0.0.1:%d' % PORTS['ctl']
PW = 'ein-langes-passwort'
SHOTS = os.environ.get('SHOTS', '/tmp/shots'); os.makedirs(SHOTS, exist_ok=True)
BAD = []
NOW = lambda: int(time.time())


def ok(c, msg):
    print(('  OK     ' if c else '  FEHLER ') + msg)
    if not c: BAD.append(msg)
    return c


def ctl(cmd, **kw):
    r = urllib.request.Request(CTL, data=json.dumps(dict(cmd=cmd, **kw)).encode(), method='POST')
    return json.loads(urllib.request.urlopen(r, timeout=10).read())


def calls(cmd):
    return [c for c in ctl('calls')['calls'] if c[1] == cmd]


def waitfn(pg, expr, timeout=8000):
    """wait until a JS expression is truthy. Playwright's own wait_for_function uses eval(), which the app's Content-Security-Policy forbids (rightly);
    evaluate() goes through the debugging protocol and works."""
    end = time.time() + timeout / 1000.0
    while time.time() < end:
        try:
            if pg.evaluate(expr):
                return True
        except Exception:
            pass
        pg.wait_for_timeout(150)
    raise AssertionError('Zeitüberschreitung beim Warten auf: ' + expr[:120])


def refresh(page, wait=350):
    ctl('invalidate')
    page.click('[data-act=refresh]'); page.wait_for_timeout(wait)


class Txt(str):
    """the VISIBLE text: the style sheet sets headings and chips in capitals, so `in` ignores case"""
    def __contains__(self, item):
        return str.__contains__(self.lower(), str(item).lower())


def text(page, sel):
    return Txt(page.inner_text(sel))


FAKE_PUSH = """
(() => {
  const b64 = (n) => btoa(String.fromCharCode(...Array.from({length: n}, (_, i) => (i * 7 + 3) % 256))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  let sub = null;
  const mk = () => ({ endpoint: 'https://fcm.googleapis.com/fcm/send/e2e-device', toJSON() { return { endpoint: this.endpoint, keys: { p256dh: b64(65), auth: b64(16) } }; }, unsubscribe() { sub = null; return Promise.resolve(true); } });
  Notification.requestPermission = () => Promise.resolve('granted');
  Object.defineProperty(Notification, 'permission', { get: () => 'granted' });
  PushManager.prototype.subscribe = function () { sub = mk(); return Promise.resolve(sub); };
  PushManager.prototype.getSubscription = function () { return Promise.resolve(sub); };
})();
"""


def run():
    errors = []
    with sync_playwright() as pw:
        br = pw.chromium.launch()
        ctx = br.new_context(viewport={'width': 412, 'height': 915}, device_scale_factor=2, is_mobile=True, has_touch=True, locale='de-DE')
        ctx.add_init_script(FAKE_PUSH)
        page = ctx.new_page()
        page.on('pageerror', lambda e: errors.append('pageerror: ' + str(e)))
        page.on('console', lambda m: errors.append('console: ' + m.text) if m.type == 'error' and 'Failed to load resource' not in m.text else None)
        page.on('dialog', lambda d: d.dismiss())

        print('== 1. Anmeldung')
        page.goto(BASE); page.wait_for_selector('#lf')
        ok(page.evaluate("document.querySelector('.login canvas') !== null"), 'der Kern ist schon auf dem Anmeldebild zu sehen')
        page.fill('#pw', 'falsch'); page.click('#lf .btn'); waitfn(page, "document.querySelector('#lerr').textContent.length > 0")
        ok('Falsches Passwort' in text(page, '#lerr'), 'falsches Passwort: klare Meldung')
        page.fill('#pw', PW); page.click('#lf .btn'); page.wait_for_selector('.shell')
        ok(page.evaluate("document.cookie === ''"), 'das Sitzungs-Cookie ist für Skripte unsichtbar (HttpOnly)')

        print('== 2. Kern')
        waitfn(page, "document.querySelector('#hud b') && document.querySelector('#hud b').textContent === 'RUHIG'", timeout=8000)
        page.wait_for_timeout(1200)
        w, h, n = page.evaluate("(() => { const c = document.querySelector('#coreStage canvas'); const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data; let n = 0; for (let i = 3; i < d.length; i += 4) if (d[i] > 0) n++; return [c.width, c.height, n]; })()")
        ok(w > 300 and h > 300 and n > 3000, 'die Kern-Animation zeichnet wirklich (Leinwand %dx%d, %d gezeichnete Pixel)' % (w, h, n))
        ok('Keine Vorfälle. Die DNS-Sperren greifen' in text(page, '#lage .lage-text'), 'Lagetext aus der Firewall')
        ok(page.locator('#factsCard .facts > div').count() == 3 and page.locator('.pulse button').count() == 8, 'Fakten (3) und Verlauf der letzten Analysen (8)')
        ok('RUHIG' in text(page, '#lage'), 'Stufe ruhig')
        page.screenshot(path=SHOTS + '/mobil-kern.png')
        ctl('status', patch={'last': {'findings': [{'title': 'Neues Land', 'text': 'kamera-hof spricht erstmals mit Irland.', 'ref': 'kamera-hof', 'src': 'lernmodus'}]}}); refresh(page)
        page.click('#lage summary'); ok(page.evaluate("document.querySelector('#lage details').open"), 'die Befunde klappen auf')
        page.wait_for_timeout(7500)
        ok(page.evaluate("document.querySelector('#lage details').open"), 'und bleiben nach einer Aktualisierung aufgeklappt (es wird nur bei geändertem Inhalt neu gezeichnet)')
        ctl('status', patch={'last': {'findings': []}})

        print('== 3. Vorschläge')
        ctl('proposals', list=[
            {'id': 'iso:192.168.1.90:1790912487', 'type': 'isolate', 'ip': '192.168.1.90', 'score': 90, 'sources': ['dns', 'radar', 'suricata'], 'seconds': 86400},
            {'id': 'dns:doh', 'type': 'dns', 'descr': 'DoH-Resolver sperren (HaGeZi-Liste, IPv4)', 'blocked_reason': 'Beobachtungszeit 7 h von 24 h'},
            {'id': 'shp:apply', 'type': 'shaper', 'add_ms': 73.0, 'down_bw': 425, 'up_bw': 30}])
        refresh(page)
        ok('Wartet auf dich · 3' in text(page, '#wait'), 'drei Vorschläge warten')
        ok('kamera-hof (192.168.1.90) isolieren' in text(page, '#wait'), 'der Vorschlag nennt das Gerät beim Namen: kamera-hof (192.168.1.90)')
        ok(page.locator('[data-badge=core]:visible').first.inner_text() == '3', 'Zähler an der Navigation: 3')
        ok(page.locator('#wait [data-act=prop-do]').count() == 2, 'der blockierte Vorschlag hat keinen „Ausführen“-Knopf, nur „Ablehnen“')
        ok('Beobachtungszeit 7 h' in text(page, '#wait'), 'er sagt, worauf er wartet')
        page.screenshot(path=SHOTS + '/mobil-vorschlaege.png')
        page.click('#wait [data-act=prop-do] >> nth=0'); page.wait_for_selector('.sheet')
        ok('kamera-hof (192.168.1.90) isolieren' in text(page, '.sheet') and 'Eine Woche' in text(page, '.sheet'), 'Bestätigungsfrage nennt die Maßnahme')
        page.keyboard.press('Escape'); ok(page.locator('.sheet').count() == 0 and not calls('do'), 'Escape bricht ab, nichts wurde gesendet')
        page.click('#wait [data-act=prop-do] >> nth=0'); page.click('#shOk'); page.wait_for_timeout(600)
        ok(any(c[2] == 'iso:192.168.1.90:1790912487' for c in calls('do')), 'nach der Bestätigung ging „do“ mit der richtigen Kennung an die Firewall')
        refresh(page); ok('Wartet auf dich · 2' in text(page, '#wait'), 'der ausgeführte Vorschlag ist weg')
        page.click('#wait [data-act=prop-no] >> nth=0'); page.wait_for_timeout(500)
        ok(len(calls('dismiss')) == 1, '„Ablehnen“ wird ohne Rückfrage gesendet')
        ctl('status', patch={'names': {'192.168.1.92': '<b>fett</b> & "x"'}})
        ctl('proposals', list=[{'id': 'iso:192.168.1.92:5', 'type': 'isolate', 'ip': '192.168.1.92', 'score': 70, 'sources': ['dns']}]); refresh(page)
        ok('<b>fett</b> & "x" (192.168.1.92) isolieren' in text(page, '#wait'), 'ein Gerätename voller Sonderzeichen erscheint als Text, nicht als HTML')
        ok(page.locator('#wait b b').count() == 0, 'und erzeugt kein Element')
        page.click('#wait [data-act=prop-do]'); page.wait_for_selector('.sheet')
        ok('<b>fett</b> & "x" (192.168.1.92) isolieren' in text(page, '.sheet') and '&amp;' not in text(page, '.sheet'), 'auch die Bestätigungsfrage zeigt ihn genau einmal maskiert (kein „&amp;“)')
        page.keyboard.press('Escape')
        ctl('proposals', list=[]); refresh(page)

        print('== 4. Analyse')
        ctl('next_scan', value={'level': 'watch', 'summary': 'Ein Gerät fragt DNS an der Firewall vorbei.'})
        page.click('[data-act=analyze]'); waitfn(page, "document.querySelector('#hud b').textContent === 'DENKT'", timeout=5000)
        ok(page.locator('[data-act=analyze]').is_disabled(), 'während sie denkt, ist der Knopf gesperrt, der Kern wird violett (DENKT)')
        waitfn(page, "document.querySelector('#hud b').textContent === 'BEOBACHTEN'", timeout=14000)
        ok('fragt DNS an der Firewall vorbei' in text(page, '#lage') and 'BEOBACHTEN' in text(page, '#lage'), 'das Ergebnis erscheint, Stufe BEOBACHTEN, der Kern färbt sich um')
        ctl('status', patch={'level': 'calm'})

        print('== 5. Aufträge')
        page.click('.tabbar [data-v=tasks]'); page.wait_for_selector('#taskText')
        page.fill('#taskText', 'abc'); page.wait_for_timeout(7000)
        ok(page.input_value('#taskText') == 'abc', 'ein angefangener Text überlebt die Aktualisierung')
        page.click('[data-act=chip] >> nth=3'); ok('DNS-Sperren' in page.input_value('#taskText'), 'ein Vorschlags-Knopf füllt das Feld')
        page.fill('#taskText', 'Prüfe, warum das Gerät kamera-hof Probleme macht'); page.click('[data-act=send-task]')
        page.wait_for_selector('#taskList .item'); ok(any(c[2] == 'Prüfe, warum das Gerät kamera-hof Probleme macht' for c in calls('task')), 'der Auftrag kam bei der Firewall an')
        ok('wartet' in text(page, '#taskList'), 'er steht als „wartet“ in der Liste')
        waitfn(page, "document.querySelector('#taskList').innerText.toLowerCase().includes('fertig')", timeout=12000)
        ok('neuen Land' in text(page, '#taskList'), 'die Antwort erscheint von selbst')
        ctl('task_answer', value={'answer': '<img src=x onerror="window.__xss=1"> Hallo <script>window.__xss=2</script>', 'actions': [
            {'id': 'dns:rdr', 'label': 'DNS umleiten (Schritt 1)', 'blocked': ''}, {'id': 'shp:apply', 'label': 'Traffic-Shaping einrichten', 'blocked': 'Zugang für Regeländerungen fehlt'}]})
        page.fill('#taskText', 'Test Einschleusung'); page.click('[data-act=send-task]')
        waitfn(page, "document.querySelector('#taskList').innerText.includes('Hallo')", timeout=12000); page.wait_for_timeout(400)
        ok(page.evaluate("window.__xss === undefined"), 'Skript im Modell-Text wird NICHT ausgeführt')
        ok('<img src=x' in text(page, '#taskList'), 'es wird als Text angezeigt, nicht als Bild')
        ok(page.locator('#taskList [data-act=task-do]').count() == 2 and page.locator('#taskList [data-act=task-do][disabled]').count() == 1, 'die Maßnahme aus dem Auftrag ist ausführbar, die blockierte nicht (mit Grund)')
        ctl('task_answer', value={'answer': 'Das Gerät hat in den letzten 24 Stunden 12 Verbindungen zu einem neuen Land aufgebaut.', 'actions': []})
        page.screenshot(path=SHOTS + '/mobil-auftraege.png')

        print('== 6. Befunde')
        ctl('inv', value={'items': [{'id': 2, 't': NOW() - 600, 'ok': True, 'ip': '192.168.1.90', 'name': 'kamera-hof', 'anlass': 'Vorfall mit Wert 90 aus dns, radar, suricata', 'urteil': 'verdaechtig',
                                     'begruendung': 'Upload 32,9× über dem Grenzwert, dazu eine Suricata-Meldung zu Datenabfluss.', 'unbelegt': ['4711'], 'tools': [{'name': 'vorfaelle', 'warum': 'Was die Quellen melden'}],
                                     'belege': ['vorfaelle: Upload 32,9× über dem Grenzwert'], 'plan': [{'aktion': 'isolieren', 'warum': 'Datenabfluss stoppen', 'link': 'iso:192.168.1.90:1790912487', 'status': 'vorschlag', 'hinweis': ''},
                                                                                                    {'aktion': 'richtlinie', 'warum': 'nur gelernte Dienste', 'link': '', 'status': 'empfehlung', 'hinweis': 'Testmodus läuft seit 0.8 von 3 Tagen'}]}],
                          'queue': [], 'running': None, 'today': 1, 'max_day': 6, 'next': ''})
        page.click('.tabbar [data-v=insight]'); refresh(page)
        ok('kamera-hof' in text(page, '#insBody') and 'VERDÄCHTIG' in text(page, '#insBody') and 'VORSCHLAG' in text(page, '#insBody'), 'Untersuchung mit Urteil und Plan')
        ok('4711' in text(page, '#insBody'), 'eine nicht belegte Zahl wird gewarnt')
        ok(page.locator('[data-act=inv-do]').count() == 1, 'nur der Vorschlag ist ausführbar, die Empfehlung nicht')
        page.fill('#invIp', 'abc'); page.click('[data-act=inv-now]'); page.wait_for_selector('.toast.bad')
        ok('keine gültige IP' in text(page, '.toast.bad'), 'eine ungültige Adresse wird abgelehnt, bevor sie die Firewall sieht')
        ok(not calls('invnow'), 'und nichts wurde gesendet')
        page.click('[data-act=refresh]'); page.wait_for_timeout(100); page.fill('#invIp', 'xyz'); page.click('[data-act=inv-now]'); page.wait_for_selector('.toast.bad'); page.wait_for_timeout(150)
        ok(page.locator('.toast').count() == 1, 'nie zwei Hinweise übereinander: ein neuer ersetzt den alten')
        ctl('inv', value={'items': [], 'queue': [{'ip': '192.168.1.91', 'key': 'm', 'anlass': 'von dir angestoßen'}], 'running': None, 'today': 0, 'max_day': 6, 'next': ''})
        page.fill('#invIp', '192.168.1.91'); page.click('[data-act=inv-now]'); page.wait_for_timeout(500)
        ok(any(c[2] == '192.168.1.91' for c in calls('invnow')), 'eine gültige Adresse wird eingeplant'); refresh(page)
        ok('wartet' in text(page, '#insBody') and '192.168.1.91' in text(page, '#insBody'), 'sie steht als wartend da')
        page.click('[data-act=seg][data-t=imp]'); ok('DoH-Domains auch in Unbound' in text(page, '#insBody'), 'Reiter „Verbessern“ zeigt die Verbesserungen')
        page.click('[data-act=imp-ask]'); page.wait_for_selector('#taskText'); page.wait_for_timeout(200)
        ok('DoH-Domains' in page.input_value('#taskText'), '„Als Auftrag fragen“ springt zu den Aufträgen und füllt den Text')

        print('== 7. Aktionen')
        ctl('action', entry={'type': 'isolate', 'ip': '192.168.1.90', 'descr': 'kamera-hof', 'active': True, 'probation_until': NOW() + 5 * 86400, 'left': 3600})
        ctl('action', entry={'type': 'dns', 'descr': 'DoH-Resolver sperren', 'result': 'failed', 'error': 'HTTP 500'})
        page.click('.tabbar [data-v=actions]'); refresh(page)
        ok('Isoliert' in text(page, '#actLog') and 'fehlgeschlagen' in text(page, '#actLog') and 'auf Probe bis' in text(page, '#actLog'), 'Protokoll mit Probezeit und Fehlschlag')
        ok('kamera-hof' in text(page, '#actLog'), 'im Protokoll steht der Name statt nur der Adresse')
        ok('Autonom' in text(page, '#actTop') and 'automatisch' in text(page, '#actTop'), 'Autonomie-Übersicht')
        page.screenshot(path=SHOTS + '/mobil-aktionen.png')
        page.click('[data-act=release]'); page.wait_for_selector('.sheet')
        ok('Veto einlegen' in text(page, '.sheet'), 'während der Probezeit heißt es „Veto“')
        page.click('#shOk'); page.wait_for_timeout(500); ok(len(calls('release')) == 1, 'das Veto geht an die Firewall')
        page.click('[data-act=noaus]'); page.wait_for_selector('#shF')
        ok(page.locator('#shOk').is_disabled(), 'Not-Aus: der Knopf ist gesperrt …')
        page.fill('#shF', 'nicht'); ok(page.locator('#shOk').is_disabled(), '… auch bei falschem Wort')
        page.fill('#shF', 'not-aus'); ok(page.locator('#shOk').is_enabled(), '… und frei erst nach dem Wort NOT-AUS')
        page.click('#shOk'); page.wait_for_timeout(500); ok(len(calls('noaus')) == 1, 'Not-Aus wurde ausgelöst')

        print('== 8. Mehr: Verbindung, Meldungen, Zertifikat')
        page.click('.tabbar [data-v=more]'); page.wait_for_selector('#moreBody .card'); page.wait_for_timeout(400)
        fp = page.inner_text('pre.fp')
        ok('127.0.0.1' in text(page, '#moreBody') and fp.count(':') == 31 and 'verbunden' in text(page, '#moreBody'), 'Verbindungskarte mit Adresse und Fingerabdruck')
        page.screenshot(path=SHOTS + '/mobil-mehr.png')
        page.click('[data-pref=scan]'); page.wait_for_timeout(500)
        ok(ctl('prefs')['prefs']['events']['scan'] is False, 'ein Schalter ändert die Einstellung auf dem Server')
        page.click('[data-act=lvl][data-l=alert]'); page.wait_for_timeout(400); ok(ctl('prefs')['prefs']['level'] == 'alert', 'Mindeststufe „Alarm“ wird gespeichert')
        page.click('[data-pref=quiet]'); page.wait_for_selector('[data-q=from]')
        page.fill('[data-q=from]', '23:30'); page.dispatch_event('[data-q=from]', 'change'); page.wait_for_timeout(400)
        q = ctl('prefs')['prefs']['quiet']; ok(q['on'] is True and q['from'] == '23:30', 'Ruhezeiten werden gespeichert (%s)' % q)
        page.click('[data-act=push-on]'); waitfn(page, "document.querySelector('#moreBody').innerText.includes('Auf diesem Gerät') && document.querySelector('[data-act=push-off]')", timeout=6000)
        subs = ctl('subs')['subs']; ok(len(subs) == 1 and subs[0]['sub']['endpoint'].startswith('https://fcm.googleapis.com/'), 'das Gerät ist für Push angemeldet')
        page.click('[data-act=push-off]'); page.wait_for_timeout(700); ok(ctl('subs')['subs'] == [], 'und lässt sich wieder abmelden')
        ctl('rotate'); refresh(page, 600)
        ok('Zertifikat der Firewall hat sich geändert' in text(page, '#moreBody') or page.locator('.banner.bad').count() > 0, 'ein geändertes Zertifikat wird laut gemeldet')
        page.click('[data-act=pin-trust]'); page.wait_for_selector('#shF')
        page.fill('#shF', 'kurz'); ok(page.locator('#shOk').is_disabled(), 'Zertifikat bestätigen braucht das Passwort')
        page.fill('#shF', 'falsches-passwort'); page.click('#shOk'); page.wait_for_selector('.toast.bad'); ok('Falsches Passwort' in text(page, '.toast.bad'), 'falsches Passwort: abgelehnt')
        page.wait_for_timeout(2800)
        page.click('[data-act=pin-trust]'); page.wait_for_selector('#shF'); page.fill('#shF', PW); page.click('#shOk'); page.wait_for_timeout(900); refresh(page, 600)
        ok(page.locator('.banner.bad').count() == 0 and 'verbunden' in text(page, '#moreBody'), 'mit dem Passwort ist das neue Zertifikat bestätigt, die Verbindung steht wieder')

        print('== 9. Ausfälle')
        page.click('.tabbar [data-v=core]'); page.wait_for_selector('#lage')
        ctl('mode', value='drop'); refresh(page, 700)
        ok(page.locator('.banner').count() > 0 and 'nicht erreichbar' in text(page, '#banner') or 'unterbrochen' in text(page, '#banner'), 'ausgefallene Firewall: Hinweis')
        ok(page.locator('#stale').is_visible() and 'Stand' in text(page, '#stale'), 'der Stand wird als alt gekennzeichnet')
        ok(text(page, '#hud b') in ('RUHIG', 'BEOBACHTEN'), 'und zeigt weiter den letzten Stand')
        ctl('mode', value=None); refresh(page, 700); ok(page.locator('.banner').count() == 0 and not page.locator('#stale').is_visible(), 'wieder da: Hinweis weg')
        page.evaluate("navigator.serviceWorker.ready"); page.wait_for_timeout(800)
        ctx.set_offline(True); page.click('[data-act=refresh]'); page.wait_for_selector('.banner'); ok('Keine Verbindung zum Companion' in text(page, '#banner'), 'Browser ohne Netz: Hinweis')
        ok(text(page, '#lage .lage-text') != '', 'der letzte Stand bleibt sichtbar')
        page.reload(); page.wait_for_selector('.shell', timeout=8000); page.wait_for_timeout(600)
        ok(page.locator('.shell').count() == 1 and text(page, '#lage .lage-text') != '', 'Neustart OHNE Verbindung: die App startet aus dem Zwischenspeicher mit dem letzten Stand')
        ctx.set_offline(False); page.wait_for_timeout(7500); ok(page.locator('.banner').count() == 0, 'mit Verbindung verschwindet der Hinweis von selbst')

        print('== 10. Desktop')
        d = br.new_context(viewport={'width': 1366, 'height': 800}, locale='de-DE'); dp = d.new_page()
        dp.on('pageerror', lambda e: errors.append('pageerror: ' + str(e)))
        dp.goto(BASE); dp.fill('#pw', PW); dp.click('#lf .btn'); dp.wait_for_selector('.shell'); waitfn(dp, "document.querySelector('#hud b') && document.querySelector('#hud b').textContent.length > 0"); dp.wait_for_timeout(1500)
        ok(dp.locator('.rail').is_visible() and not dp.locator('.tabbar').is_visible(), 'Desktop: Seitenleiste statt unterer Leiste')
        a, b = dp.locator('#coreStage').bounding_box(), dp.locator('.core-side').bounding_box()
        ok(a['x'] + a['width'] <= b['x'] + 6 and abs(a['y'] - b['y']) < 120, 'Desktop: Kern links, Lage rechts daneben (zwei Spalten)')
        dp.screenshot(path=SHOTS + '/desktop-kern.png')
        dp.set_viewport_size({'width': 390, 'height': 800}); dp.wait_for_timeout(500)
        ok(dp.locator('.tabbar').is_visible() and not dp.locator('.rail').is_visible(), 'schmaler: wieder die untere Leiste')
        s = dp.locator('#coreStage canvas').bounding_box(); ok(abs(s['width'] - s['height']) < 2, 'der Kern bleibt rund (%dx%d)' % (s['width'], s['height']))
        d.close()
        br.close()
    print('== 11. Fehler im Browser')
    ok(errors == [], 'keine JavaScript-Fehler und keine Verstöße gegen die Sicherheitsrichtlinie: %s' % errors[:3])
    print('\nERGEBNIS:', 'ALLE PRÜFUNGEN BESTANDEN' if not BAD else '%d FEHLER: %s' % (len(BAD), BAD))
    sys.exit(1 if BAD else 0)


run()
