# S.A.R.A.H. Companion

Die Web-App für die KI-Wächterin deiner Firewall. Auf dem Handy und am Desktop, installierbar wie eine App.

- **Kern** – derselbe Kern wie in OPNsense, mit Lage, Fakten und dem Verlauf der letzten Analysen. „Jetzt analysieren“ per Fingertipp.
- **Aufträge** – gib ihr Aufgaben: *„Prüfe, warum das Gerät kamera-hof Probleme macht“*. Auch per Sprache. Sie antwortet mit dem, was sie in den Daten findet, und bietet Maßnahmen an, die **du** bestätigst.
- **Befunde** – ihre Untersuchungen (was sie sich angesehen hat, Urteil, Plan) und ihre Verbesserungsvorschläge. Ein Gerät kannst du selbst untersuchen lassen.
- **Aktionen** – was sie getan hat, mit Probezeit und **Veto**. Dazu der **Not-Aus**.
- **Meldungen** – nach einem Scan, der nicht ruhig ist; bei einem Vorfall; wenn sie selbst gehandelt hat; wenn etwas auf dich wartet; wenn die Firewall nicht erreichbar ist. **Ein ruhiger Scan meldet sich nie.** Mit Ruhezeiten.

```
Handy / Desktop  ──https──►  Companion (Docker)  ──https + API-Schlüssel──►  OPNsense (Plugin os-scdeck)
 nur die Oberfläche           hält den Schlüssel,                              S.A.R.A.H.
 und dein Passwort            prüft das Zertifikat, schickt Push
```

Der Container hält den Schlüssel und spricht mit der Firewall. **Dein Handy sieht den Schlüssel nie.** Push kommt vom Container, jede Minute geprüft.

## 1. In OPNsense: Benutzer und Schlüssel

Plugin **os-scdeck ab 0.31** (ab 0.25 geht fast alles; „Untersuchen“ braucht 0.25; **Gerätenamen** wie „kamera-hof (192.168.1.90)“ statt nur der Adresse gibt es ab 0.31).

1. *System › Zugang › Benutzer* → neuer Benutzer, z. B. `sarah-app`. Kein Passwort-Login nötig.
2. Recht **„DECK: S.A.R.A.H. (Apps)“** zuweisen. Das erlaubt nur `api/scdeck/stats/sarah*`, sonst nichts.
3. Beim Benutzer *API-Schlüssel* erzeugen. Die heruntergeladene Datei enthält `key=` und `secret=`.

> Dieser Schlüssel kann an der S.A.R.A.H.-Schnittstelle technisch auch Einstellungen ändern. Der Companion sendet das **nie** (er kennt nur eine feste Liste von Befehlen), aber behandle den Schlüssel wie ein Passwort.

Die Firewall muss vom Docker-Host aus auf die Web-Oberfläche (meist Port 443) erreichbar sein.

## 2. Installieren: GitHub baut, Unraid zieht

Wie bei deinen anderen Apps: Du schiebst den Code mit GitHub Desktop nach GitHub, **GitHub baut das Image selbst** und legt es auf `ghcr.io/xruchai86/sarah-companion` ab; Unraid zieht es von dort. Kein Docker auf deinem Rechner nötig.

**Einmalig einrichten**

1. GitHub Desktop: *File › New repository* → Name `sarah-companion`. **„Keep this code private“ nicht ankreuzen** (sonst kann Unraid die Vorlage und das Symbol nicht lesen und das Paket ist privat).
2. Den Inhalt dieses Archivs **direkt in den Repository-Ordner** kopieren, sodass `Dockerfile`, `sarah-companion.xml` und der Ordner `.github` im obersten Ordner liegen, **nicht** in einem Unterordner `sarah-companion/sarah-companion/`. Der Ordner `.github` muss mit.
3. GitHub Desktop: *Commit to main* → *Publish repository* (später: *Push origin*).
4. Auf github.com im Repository den Reiter **Actions** öffnen: Der Lauf „docker“ baut das Image (ca. 3 bis 5 Minuten). **Grün = fertig.** Rot: auf den Lauf klicken, der rote Schritt zeigt die Fehlermeldung.
5. Das Paket **öffentlich** stellen (sonst kann Unraid es nicht laden): github.com/xruchai86 › *Packages* › `sarah-companion` › *Package settings* › *Change visibility* › *Public*.
6. Unraid: `https://github.com/xruchai86/sarah-companion` dort als Vorlagen-Quelle eintragen, wo du es auch bei deinen anderen Apps getan hast. Alternativ die Datei `sarah-companion.xml` nach `/boot/config/plugins/dockerMan/templates-user/` kopieren. Dann *Docker › Container hinzufügen › sarah-companion*, Felder ausfüllen (Adresse, Schlüssel, Geheimnis, Passwort), *Apply*.

**Danach:** Jeder Push auf `main` baut ein neues Image (`latest`). In Unraid reicht *Aktualisieren*. Mit einem Tag wie `v1.0.2` (GitHub Desktop: *History › Rechtsklick › Create Tag*) gibt es zusätzlich ein Image mit dieser Versionsnummer.

Die Tests laufen vor jedem Bau; ein Fehler darin stoppt die Veröffentlichung, es entsteht kein kaputtes Image.

**Gepflegt und nachprüfbar:** Vor jedem Bau prüft `pip-audit` die eingefrorenen Abhängigkeiten auf bekannte Schwachstellen (ein Fund stoppt den Bau). Dependabot schlägt jede Woche Updates für Python-Pakete, das Basisimage und die GitHub-Actions vor; du siehst sie unter *Pull requests* und übernimmst sie mit einem Klick, der Bau prüft sie vorher. Jedes Image trägt eine Stückliste (SBOM) und einen Herkunftsnachweis. Das Image selbst wird in zwei Stufen gebaut: Im laufenden Container gibt es weder `pip` noch Bauwerkzeuge, er läuft nie als root, nur `/data` ist beschreibbar.

| Meldung | Ursache |
|---|---|
| Unraid: `pull access denied` / `unauthorized` | Das Paket ist noch **privat** (Schritt 5), oder du hast es mit anderem Namen angelegt. |
| Unraid: `manifest unknown` / `not found` | Der Lauf in *Actions* ist noch nicht grün, oder er war rot. |
| Actions: „Workflow not found“ / nichts läuft | `.github/workflows/docker.yml` liegt nicht im obersten Ordner (verschachtelt kopiert, oder `.github` vergessen). |
| Actions rot im Schritt *Tests* | Die Meldung im Log lesen; die Tests prüfen auch, dass Vorlage, Workflow und Dockerfile zusammenpassen. |
| Actions rot im Schritt *login* / `write_package` | Repository › *Settings › Actions › General › Workflow permissions*: **Read and write permissions**. |

**Ohne GitHub (lokal, z. B. Docker Compose):** `docker-compose.yml` zieht dasselbe Image. Zum lokalen Bauen die Zeile `# build: .` statt `image:` einschalten und `docker compose up -d --build`.

Beim **ersten Kontakt** merkt sich der Container den SHA-256-Fingerabdruck des Zertifikats der Firewall (selbst signiert ist in Ordnung). Ändert sich das Zertifikat später, sendet er **nichts mehr**, bis du unter *Mehr › Verbindung* mit deinem Passwort bestätigst. Hast du ein Zertifikat einer echten Zertifizierungsstelle: `OPNSENSE_VERIFY=system`.

## 3. HTTPS (nötig für Push und „App installieren“)

Browser erlauben Push und Installation nur über **https** (oder `localhost`). Ohne https läuft die App trotzdem, aber ohne Meldungen. Beispiel mit Traefik (`TRUST_PROXY=1` setzen):

```yaml
    labels:
      - traefik.enable=true
      - traefik.http.routers.sarah.rule=Host(`sarah.example.org`)
      - traefik.http.routers.sarah.entrypoints=websecure
      - traefik.http.routers.sarah.tls.certresolver=letsencrypt
      - traefik.http.services.sarah.loadbalancer.server.port=8080
```

Willst du sie nicht ins Internet stellen: Erreichbar nur im Heimnetz oder über dein VPN reicht. Die Push-Nachrichten selbst laufen über den Push-Dienst deines Browsers (bei Android Google, bei Firefox Mozilla, bei Apple Apple); der Inhalt ist Ende-zu-Ende verschlüsselt, der Dienst sieht nur, dass es eine Nachricht gibt. Willst du das nicht: `NTFY_URL` und `NTFY_TOPIC` für einen eigenen ntfy-Server setzen.

## 4. Auf dem Handy

1. Adresse öffnen, Passwort eingeben.
2. **Android (Chrome):** Menü › *App installieren* – oder *Mehr › App › Installieren*.
   **iPhone/iPad (Safari, ab iOS 16.4):** Teilen › *Zum Home-Bildschirm*. Erst dann sind Push-Meldungen möglich.
3. *Mehr › Benachrichtigungen › Einschalten*, Erlaubnis geben, mit *Test* prüfen.

## 5. Wann sie dich anstupst

| Meldung | Wann |
|---|---|
| Scan | Ein **fertiger** Scan ist *Beobachten* oder *Alarm* (mindestens die gewählte Stufe). Ruhig → nie. |
| Vorfall | Ein Vorfall öffnet sich, auch zwischen den Scans. |
| Eingriff | S.A.R.A.H. hat selbst gehandelt (mit Hinweis aufs Veto) oder ein Eingriff schlug fehl. |
| Untersuchung | Ergebnis *verdächtig* oder *gefährlich*. |
| Wartet auf dich | Ein neuer Vorschlag braucht deine Entscheidung. |
| Firewall nicht erreichbar | Seit 10 Minuten keine Verbindung, und wenn sie wieder da ist. Ein **geändertes Zertifikat** sofort. |

Beim ersten Start meldet sie nichts Altes (nur ab jetzt). In den **Ruhezeiten** kommt nur ein Alarm durch; alles andere wartet und kommt als **eine** Sammelmeldung. Auf dem Startbildschirm zeigt die App die Zahl der wartenden Vorschläge als Zähler am Symbol (wo das Gerät es kann).

## 6. Sicherheit

Weil der Container den Schlüssel hält, ist die Oberfläche das Ziel. Deshalb:

- Passwort (mindestens 8 Zeichen, gehasht, **5 Fehlversuche sperren eine Minute, dann doppelt so lang**). Ohne Passwort startet der Container nicht.
- Sitzungs-Cookie `HttpOnly`, `SameSite=Strict`, auf https `Secure`; jede Änderung braucht einen Header, den eine fremde Webseite nicht senden kann.
- **Kein Weiterleiter:** nur die feste Liste (`analyze`, `task`, `tasks`, `inv`, `invnow`, `do`, `dismiss`, `release`, `noaus`), jeweils mit denselben Eingabeprüfungen wie die Firewall.
- Ein Push-Abo darf nur auf bekannte Push-Dienste zeigen (keine internen Adressen).
- Zertifikat der Firewall gemerkt; bei Abweichung wird nichts gesendet.
- Strenge Sicherheitsrichtlinie (CSP, keine fremden Ressourcen, kein Inline-Skript), der Text von Firewall und Sprachmodell wird nie als HTML ausgewertet.
- Der Container läuft ohne Root, nur `/data` ist beschreibbar. Dort liegen Zertifikat-Fingerabdruck, Push-Geräte, Einstellungen und der Push-Schlüssel (alle Rechte 600), **nicht** der Firewall-Schlüssel.
- Tipp: Stelle zusätzlich Authentik/Forward-Auth davor, wenn du sie von außen erreichbar machst.

## 7. Fehlersuche

| Meldung | Ursache |
|---|---|
| „Die Firewall lehnt den Zugang ab“ | Schlüssel/Geheimnis falsch, oder dem Benutzer fehlt „DECK: S.A.R.A.H. (Apps)“. |
| „Die Schnittstelle gibt es dort nicht“ | Plugin os-scdeck fehlt oder ist älter als 0.17; Adresse prüfen. |
| „Das Zertifikat der Firewall hat sich geändert“ | Hast du es erneuert? Dann *Mehr › Zertifikat erneut bestätigen*. Wenn nicht: nicht bestätigen und nachforschen. |
| „Keine Verbindung zur Firewall“ | Netz/Firewall-Regel zwischen Docker-Host und Web-Oberfläche. |
| Push kommt nicht an | Läuft die App über https? Erlaubnis gegeben? *Test* gedrückt? Auf Android: Akku-Optimierung für den Browser/die App ausschalten. Auf iPhone: erst zum Home-Bildschirm hinzufügen. |
| „Zu viele Versuche“ | Passwort 5× falsch; warte die genannte Zeit. |

## 8. Entwicklung und Tests

```
python -m venv .venv && .venv/bin/pip install -r requirements.txt -c constraints.txt pytest pyyaml
.venv/bin/python -m pytest -q tests/                 # Server, Firewall-Client, Meldungslogik, Zustellung
.venv/bin/python tests/smoke.py                      # startet wie der Container (python -m app)
python tools/make_icons.py                           # nur nach Änderungen am Kern-Symbol (Playwright)
.venv/bin/python tests/devserver.py &                # dann: python tests/e2e.py <Protokolldatei>   (Browser-Test, Playwright)
```

Geprüft: Zertifikat-Merken und -Ablehnen gegen eine nachgebaute Firewall (echtes TLS), jede Eingabeprüfung, alle Meldungsfälle als reine Funktion, **echter Web Push mit VAPID, verschlüsselt und im Test wie vom Browser entschlüsselt**, die komplette Oberfläche in Chromium (Handy- und Desktop-Maße, Ausfälle, Offline-Start, Zertifikatswechsel, Skript-Einschleusung durch Modelltext).

## 9. Ehrliche Grenzen

- **Nicht gegen deine echte Firewall und nicht auf einem echten Handy getestet.** Die Firewall ist nachgebaut (Formen aus dem Quelltext des Plugins), Push-Dienste von Google/Mozilla/Apple sind nachgebaut. Ob eine Nachricht bei deinem Gerät ankommt, zeigt erst dein *Test*-Knopf.
- Das Docker-Image selbst (`docker build`) konnte hier nicht gebaut werden (kein Docker in der Umgebung). Nachgestellt und geprüft habe ich die Schritte des Dockerfiles in einer frischen Umgebung (genau derselbe `pip install`, nur der Ordner `app`, Start mit `python -m app`, alle Dateien werden ausgeliefert) und den Test-Job des Workflows (107 Tests). Der Lauf auf GitHub selbst ist nicht geprüft.
- Einstellungen von S.A.R.A.H. (Autonomie, Modell) änderst du weiterhin in der Firewall; die App zeigt sie nur.
- Gerätenamen zeigt die App nur für Adressen, die in Vorschlägen, Protokoll oder der Untersuchungs-Warteschlange vorkommen (die Firewall liefert sie mit, ab Plugin 0.31); der App-Zugang ist bewusst auf die S.A.R.A.H.-Schnittstelle begrenzt und liest keine Geräteliste. Ohne Namen steht die Adresse da.
