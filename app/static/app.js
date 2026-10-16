/* S.A.R.A.H. Companion - the app. No framework, no external resources. Every text that comes from the firewall or from the language model is
   untrusted: it only ever enters the page through esc() (or textContent). */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

  var TASKS_ON = false;   // Aufträge per Text: abgeschaltet (zusammen mit TASKS_ON in os-scdeck scripts/scdeck/sarah.py)
  var VIEWS = [["core", "Kern"], ["incidents", "Vorfälle"], ["monitor", "Monitor"], ["tasks", "Aufträge"], ["insight", "Befunde"], ["actions", "Aktionen"], ["more", "Mehr"]].filter(function (v) { return TASKS_ON || v[0] !== "tasks"; });
  var ICON = {
    core: '<circle cx="12" cy="12" r="3"/><circle cx="12" cy="12" r="9"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>',
    tasks: '<path d="M4 5h16v11H9l-5 4z"/>', incidents: '<path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17v.5"/>', monitor: '<path d="M3 20h18M6 16V9M10 16V5M14 16v-6M18 16V8"/>', insight: '<circle cx="11" cy="11" r="6"/><path d="M16 16l5 5"/>',
    actions: '<path d="M13 2L5 14h6l-1 8 8-12h-6z"/>', more: '<path d="M4 7h16M4 12h16M4 17h16"/>'
  };
  var LEVEL = { calm: ["RUHIG", "ok"], watch: ["BEOBACHTEN", "warn"], alert: ["ALARM", "bad"] };
  var ACT = { isolate: "Isoliert", rule_off: "Regel aus", zone_expect: "Zonen gelernt", dns: "DNS-Härtung", policy: "Richtlinie", shaper: "Traffic-Shaping", release: "Aufgehoben",
    dismiss: "Abgelehnt", dry: "Nur gemeldet", pol_test: "Testmodus", noaus: "Not-Aus" };
  var CAPS = [["a_iso", "Geräte isolieren"], ["a_zone", "Zonen lernen"], ["a_rule", "Regeln abschalten"], ["a_dns", "DNS-Härtung"], ["a_pol", "Geräte-Richtlinien"], ["a_shp", "Traffic-Shaping"], ["a_inv", "Selbst untersuchen"]];
  var CAPV = { off: "aus", dry: "nur melden", on: "automatisch" };
  var MODES = { observe: "Beobachten", propose: "Vorschlagen", auto: "Autonom" };
  var EVENTS = [["scan", "Scan mit Befund", "Nach einem Scan, der nicht ruhig ist"], ["incident", "Vorfall", "Ein Vorfall öffnet sich"], ["action", "Eingriff von S.A.R.A.H.", "Mit Veto-Möglichkeit"],
    ["investigation", "Untersuchung", "Verdächtig oder gefährlich"], ["proposal", "Wartet auf dich", "Ein Vorschlag braucht deine Entscheidung"], ["offline", "Firewall nicht erreichbar", "Und: Zertifikat geändert"]];
  var CHIPS = ["Was hat sich in den letzten 24 Stunden geändert?", "Warum ist das Internet langsam?", "Welche Geräte verhalten sich ungewöhnlich?", "Sind alle DNS-Sperren aktiv?", "Prüfe, warum das Gerät "];

  var S = { me: null, data: null, err: null, cached: false, tasks: [], mounted: null, insightTab: "inv", skew: 0, busy: {}, fastUntil: 0, lastT: 0, lastAlert: false, installEvt: null, push: { supported: false }, timer: null };
  var UI = (function () { try { return Object.assign({ calm: false, vib: true }, JSON.parse(localStorage.getItem("sarah.ui") || "{}")); } catch (e) { return { calm: false, vib: true }; } })();
  function saveUi() { try { localStorage.setItem("sarah.ui", JSON.stringify(UI)); } catch (e) { /* private mode */ } }

  // ---------------------------------------------------------------- api
  function ApiError(msg, kind, status) { this.message = msg; this.kind = kind; this.status = status; }
  function api(method, path, body) {
    var opt = { method: method, headers: { "X-Requested-With": "sarah" }, credentials: "same-origin" };
    if (method !== "GET") { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body || {}); }
    return fetch(path, opt).then(function (r) {
      return r.json().catch(function () { return null; }).then(function (j) {
        if (r.status === 401 && j && j.kind === "login") { S.me = false; showLogin(); throw new ApiError("Bitte anmelden.", "login", 401); }
        if (!r.ok) throw new ApiError((j && j.error) || "Fehler " + r.status, j && j.kind, r.status);
        return j;
      });
    });
  }
  function nowS() { return Date.now() / 1000 + S.skew; }
  function ago(t) {
    if (!t) return "nie";
    var s = Math.max(0, Math.round(nowS() - t));
    if (s < 60) return "gerade eben"; if (s < 3600) return "vor " + Math.round(s / 60) + " min"; if (s < 86400) return "vor " + Math.round(s / 3600) + " h"; return "vor " + Math.round(s / 86400) + " Tagen";
  }
  function clock(t) { var d = new Date(t * 1000), p = function (n) { return (n < 10 ? "0" : "") + n; }; return p(d.getHours()) + ":" + p(d.getMinutes()); }
  function dayClock(t) { var d = new Date(t * 1000); return nowS() - t > 72000 ? d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" }) + " " + clock(t) : clock(t); }
  function setHtml(el, html) { if (!el || el._h === html) return; el._h = html; el.innerHTML = html; }
  function slotOf(el) { return { set innerHTML(v) { setHtml(el, v); }, set className(v) { if (el && el.className !== v) el.className = v; }, set hidden(v) { if (el && el.hidden !== v) el.hidden = v; } }; }
  function slot(sel) { return slotOf($(sel)); }
  function chip(txt, cls) { return '<span class="chip ' + (cls || "") + '">' + esc(txt) + "</span>"; }
  function st() { return S.data && S.data.status; }
  function toast(msg, bad) {
    $$(".toast").forEach(function (o) { o.remove(); });                      // one at a time: a new message replaces the old one instead of piling up on it
    var t = document.createElement("div"); t.className = "toast" + (bad ? " bad" : ""); t.setAttribute("role", "status"); t.textContent = msg; document.body.appendChild(t);
    setTimeout(function () { t.remove(); }, bad ? 5200 : 2600);
  }
  function errMsg(e) { return e && e.message ? e.message : "Unbekannter Fehler"; }

  // ---------------------------------------------------------------- the confirm sheet
  function sheet(o) {
    var layer = $("#layer"); if (!layer) return;
    layer.innerHTML = '<div class="veil" data-act="sheet-close"><div class="sheet" role="dialog" aria-modal="true" aria-labelledby="shT"><h2 id="shT">' + esc(o.title) + "</h2><div>" + (o.html || "") + "</div>" +
      (o.field ? '<div style="margin-top:12px"><input id="shF" type="' + (o.field.type || "text") + '" placeholder="' + esc(o.field.placeholder || "") + '" autocomplete="off" autocapitalize="off"></div>' : "") +
      '<div class="row"><button class="btn ghost" data-act="sheet-close">' + esc(o.cancel || "Abbrechen") + '</button>' + (o.ok ? '<button class="btn ' + (o.danger ? "bad" : "pri") + '" id="shOk" data-act="sheet-ok"' + (o.field ? " disabled" : "") + ">" + esc(o.ok) + "</button>" : "") + "</div></div></div>";
    var f = $("#shF"), ok = $("#shOk");
    if (f) { f.addEventListener("input", function () { ok.disabled = !(o.field.valid ? o.field.valid(f.value) : f.value.length > 0); }); f.focus(); } else if (ok) ok.focus(); else $(".sheet .btn").focus();
    S.sheet = o;
  }
  function closeSheet() { var l = $("#layer"); if (l) l.innerHTML = ""; S.sheet = null; }
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && S.sheet) closeSheet(); });

  // ---------------------------------------------------------------- login
  function showLogin() {
    stopTimers();
    document.body.innerHTML = '<div class="login"><div class="core-stage" id="lcore"></div><h1>S.A.R.A.H.</h1><form id="lf"><input id="pw" type="password" placeholder="Passwort" autocomplete="current-password" aria-label="Passwort" required>' +
      '<button class="btn pri" type="submit">Anmelden</button><div class="err" id="lerr" role="alert"></div></form></div><div id="layer"></div>';
    var cv = document.createElement("canvas"); $("#lcore").appendChild(cv);
    if (window.SarahCore) { var c = new SarahCore(cv, { state: "calm" }); if (UI.calm) c.pause(true); }
    $("#lf").addEventListener("submit", function (e) {
      e.preventDefault(); var b = $("#lf .btn"); b.disabled = true; $("#lerr").textContent = "";
      api("POST", "/api/login", { password: $("#pw").value }).then(function () { location.reload(); }).catch(function (x) { $("#lerr").textContent = errMsg(x); b.disabled = false; $("#pw").select(); });
    });
    $("#pw").focus();
  }

  // ---------------------------------------------------------------- shell
  function shell() {
    var nav = VIEWS.map(function (v) { return '<button class="nav" data-act="go" data-v="' + v[0] + '" aria-label="' + v[1] + '"><svg viewBox="0 0 24 24" aria-hidden="true">' + ICON[v[0]] + "</svg><span>" + v[1] + '</span><i class="badge" data-badge="' + v[0] + '" hidden></i></button>'; }).join("");
    document.body.innerHTML = '<div class="shell"><aside class="rail"><div class="brand">S.A.R.A.H.</div>' + nav + '</aside><div class="main"><header class="top"><span class="dot" id="dot"></span><h1>S.A.R.A.H.</h1><span class="sp"></span>' +
      '<span class="chip warn" id="stale" hidden></span><button class="btn sm ghost" data-act="refresh" aria-label="Aktualisieren">↻</button></header><main class="stage" id="view"></main></div><nav class="tabbar">' + nav + '</nav></div><div id="layer"></div>';
  }
  function route() {
    var v = (location.hash || "#core").slice(1).split("/")[0];
    if (!VIEWS.some(function (x) { return x[0] === v; })) v = "core";
    mount(v); update();
  }
  window.addEventListener("hashchange", function () { if (S.me) route(); });

  // ---------------------------------------------------------------- views: skeletons are built once, only the slots change (so a text you are typing survives the refresh)
  var SKEL = {
    core: function () { return '<div class="core-wrap"><div class="core-stage" id="coreStage"><div class="hud" id="hud"></div></div><div class="core-side"><div id="banner"></div><div class="card" id="lage"></div><div id="wait"></div><div class="card" id="factsCard"></div><div class="card" id="pulseCard"></div></div></div>'; },
    tasks: function () {
      return '<div class="card"><h3>Auftrag an S.A.R.A.H.</h3><textarea id="taskText" maxlength="1000" placeholder="z. B. Prüfe, warum das Gerät kamera-hof Probleme macht …" aria-label="Auftrag"></textarea>' +
        '<div class="row sp" style="margin-top:10px"><button class="btn mic" id="mic" data-act="mic" aria-label="Diktieren" hidden><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3"/></svg></button><button class="btn pri" data-act="send-task">Senden</button></div>' +
        '<div class="chips">' + CHIPS.map(function (c, i) { return '<button data-act="chip" data-i="' + i + '">' + esc(c.trim()) + (i === CHIPS.length - 1 ? " …" : "") + "</button>"; }).join("") + '</div></div><div class="card" id="taskList"></div>';
    },
    insight: function () { return '<div class="row" style="margin-bottom:12px"><div class="seg"><button data-act="seg" data-t="inv">Untersuchungen</button><button data-act="seg" data-t="imp">Verbessern</button></div></div><div id="insBody"></div>'; },
    actions: function () { return '<div id="actTop"></div><div class="card" id="actLog"></div><div class="danger"><div class="lbl" style="color:var(--bad)">Not-Aus</div><p class="muted" style="margin:8px 0 12px">Hebt alle aktiven Eingriffe von S.A.R.A.H. auf und schaltet alle Fähigkeiten aus. Sie bleibt im Modus „Beobachten“.</p><button class="btn bad" data-act="noaus">Not-Aus …</button></div>'; },
    incidents: function () { return '<div class="row" style="margin-bottom:12px"><div class="seg"><button data-act="iseg" data-t="live">Aktuell</button><button data-act="iseg" data-t="done">Erledigt</button></div><span class="tiny" id="incTs"></span></div><div id="incBody"></div>'; },
    monitor: function () {
      return '<div class="mon-head"><div class="seg">' + LT.map(function (t) { return '<button data-act="mon-kind" data-k="' + t[0] + '">' + t[1] + " <i></i></button>"; }).join("") + "</div>" +
        '<div class="seg">' + RANGES.map(function (r) { return '<button data-act="mon-range" data-r="' + r[0] + '">' + r[1] + "</button>"; }).join("") + "</div>" +
        '<input id="monQ" type="search" placeholder="Suchen (Signatur, Name, Meldung …)" autocomplete="off" value="' + esc(MON.f.q || "") + '">' +
        '<button class="btn sm ghost" id="monLive" data-act="mon-live">Live</button><a class="btn sm ghost" id="monCsv" href="#" download>CSV</a></div><div class="row" id="monChips" style="margin:8px 0 12px"></div><div id="monBody"></div>';
    },
    more: function () { return '<div id="moreBody"></div>'; }
  };
  var mounted = {};
  function mount(v) {
    if (S.mounted === v) return;
    unmountView();
    $("#view").innerHTML = SKEL[v](); S.mounted = v;
    $$("[data-act=go]").forEach(function (b) { b.classList.toggle("on", b.dataset.v === v); });
    if (v === "core") mountCore();
    if (v === "tasks") { loadTasks(); var mic = $("#mic"); if (mic && (window.SpeechRecognition || window.webkitSpeechRecognition)) mic.hidden = false; }
    if (v === "more") { refreshPush(); loadAn(); }
    if (v === "incidents") loadIncidents();
    $("#view").classList.toggle("wide", v === "monitor");
    if (v === "monitor") {
      monLoad(false); api("GET", "/api/logs/rules").then(function (r) { MON.rules = r || {}; if (S.mounted === "monitor") updMonitor(); }).catch(function () { /* names are a help */ });
      var q = $("#monQ"), qt = null; q.addEventListener("input", function () { clearTimeout(qt); qt = setTimeout(function () { monSearch(q.value.trim()); }, 400); });
    }
    window.scrollTo(0, 0);
  }
  function unmountView() { if (S.mounted === "core" && S.core) S.core.pause(true); if (S.rec) { try { S.rec.stop(); } catch (e) { /* not running */ } } }

  function mountCore() {
    if (!window.SarahCore) return;
    var stage = $("#coreStage"), hud = $("#hud");
    if (!S.canvas) { S.canvas = document.createElement("canvas"); stage.insertBefore(S.canvas, hud); S.core = new SarahCore(S.canvas, { state: "off" }); } else { stage.insertBefore(S.canvas, hud); S.core.fit(); }
    S.core.pause(!!UI.calm);
    if (window.ResizeObserver) { if (S.ro) S.ro.disconnect(); S.ro = new ResizeObserver(function () { if (S.core) S.core.fit(); }); S.ro.observe(stage); }
  }

  // ---------------------------------------------------------------- update: fills the slots
  function update() {
    var d = S.data, s = st();
    // header: dot and stale chip
    var dot = $("#dot"), stale = $("#stale");
    if (dot) { dot.className = "dot " + (S.err || (d && d.stale) ? "bad" : !s || !s.enabled ? "off" : lvlOf() === "alert" ? "bad" : lvlOf() === "watch" ? "warn" : ""); }
    if (stale) { var old = S.err || S.cached || (d && d.stale); stale.hidden = !old; if (old) stale.textContent = "Stand " + ago(d && d.health && d.health.ok_t || (s && s.now)); }
    var props = waiting().length;
    $$("[data-badge=core]").forEach(function (b) { b.hidden = !props; b.textContent = props; });
    if (navigator.setAppBadge) { (props ? navigator.setAppBadge(props) : navigator.clearAppBadge()).catch(function () { /* not allowed */ }); }
    var u = { core: updCore, tasks: updTasks, insight: updInsight, actions: updActions, more: updMore }[S.mounted];
    if (u) u();
  }
  function waiting() { var a = st() && st().act; return a && a.proposals ? a.proposals : []; }
  function lvlOf() { var s = st(); if (!s) return "calm"; return s.open_incident ? "alert" : (s.last && s.last.level) || s.level || "calm"; }

  function who(ip) { var n = st() && st().names && st().names[ip]; return n ? n + " (" + ip + ")" : ip; }
  function propTitle(p) {                                                    // plain text: it is escaped once, where it is shown
    if (p.type === "isolate") return who(p.ip) + " isolieren (24 h)";
    if (p.type === "rule_off") return "Regel „" + p.descr + "“ ausschalten";
    if (p.type === "dns") return "DNS: " + p.descr;
    if (p.type === "policy") return "Richtlinie für " + who(p.ip);
    if (p.type === "shaper") return "Traffic-Shaping einrichten (FQ-CoDel)";
    return String(p.descr || p.id);
  }
  function propWhy(p) {
    if (p.blocked_reason) return "Wartet: " + esc(p.blocked_reason);
    if (p.type === "dns" && p.affected && p.affected.length) return "Betrifft " + esc(p.affected.slice(0, 3).map(who).join(", ")) + (p.affected.length > 3 ? " …" : "");
    if (p.type === "isolate") return "Vorfall mit Wert " + esc(p.score) + " · " + esc((p.sources || []).join(", "));
    if (p.type === "shaper") return "Latenz unter Last +" + esc(p.add_ms) + " ms · " + esc(p.down_bw) + " / " + esc(p.up_bw) + " Mbit/s";
    return esc(p.why || p.reason || p.text || "");
  }

  function updCore() {
    var s = st(), d = S.data;
    var banner = [];
    if (S.err) banner.push(['bad', "Keine Verbindung zum Companion. " + esc(S.err)]);
    else if (d && d.stale) {
      if (d.kind === "pin") banner.push(["bad", "Das Zertifikat der Firewall hat sich geändert. Aus Sicherheitsgründen wird nichts gesendet.<br><button class=\"btn sm\" data-act=\"go\" data-v=\"more\">Prüfen</button>"]);
      else if (d.kind === "auth") banner.push(["bad", esc(d.error)]);
      else banner.push(["warn", esc(d.error || "Die Firewall ist nicht erreichbar.") + " Angezeigt wird der letzte Stand."]);
    }
    if (s) { (s.warnings || []).forEach(function (w) { banner.push(["warn", esc(w)]); }); if (s.fail) banner.push(["warn", "Letzte Analyse fehlgeschlagen: " + esc(s.fail.error)]); if (!s.enabled) banner.push(["warn", "S.A.R.A.H. ist ausgeschaltet (Einstellungen › S.A.R.A.H. in der Firewall)."]); }
    slot("#banner").innerHTML = banner.map(function (b) { return '<div class="banner ' + (b[0] === "bad" ? "bad" : "") + '" role="alert">' + b[1] + "</div>"; }).join("");
    if (!s) { slot("#lage").innerHTML = '<h3>Lage</h3><p class="muted">Warte auf die Firewall …</p>'; slot("#wait").innerHTML = ""; slot("#factsCard").hidden = true; slot("#pulseCard").hidden = true; setHud("off", "AUS", ""); return; }
    var last = s.last || {}, lv = lvlOf(), running = s.running || S.busy.analyze;
    var core = running ? "think" : (s.state || "calm");
    if (S.core) { S.core.setState(core); if (last.t && S.lastT && last.t !== S.lastT) S.core.pulse(); }
    setHud(running ? "think" : core === "act" ? "act" : core === "off" ? "off" : lv, running ? "DENKT" : core === "act" ? "HANDELT" : core === "off" ? "AUS" : LEVEL[lv][0], running ? "Analyse läuft" : "Analyse " + ago(last.t));
    S.lastT = last.t || S.lastT;
    var find = (last.findings || []).map(function (f) { return '<div class="item"><b>' + esc(f.title) + "</b><div>" + esc(f.text) + '</div><div class="tiny">' + esc(f.ref || "") + (f.src ? " · " + esc(f.src) : "") + "</div>" + (f.unbelegt ? '<div class="warnline">Zahlen, die nicht in den Daten stehen: ' + esc((f.unbelegt || []).join ? f.unbelegt.join(", ") : f.unbelegt) + "</div>" : "") + "</div>"; }).join("");
    slot("#lage").className = "card " + (lv === "alert" ? "bad" : lv === "watch" ? "warn" : "ok");
    slot("#lage").innerHTML = '<div class="row sp"><h3 style="margin:0">Lage · ' + esc(last.t ? clock(last.t) : "–") + "</h3>" + chip(LEVEL[lv][0], LEVEL[lv][1]) + "</div>" +
      '<p class="lage-text">' + esc(last.summary || (last.ok === false ? last.error : "Noch keine Analyse.")) + "</p>" + (last.level_note ? '<div class="tiny" style="margin-bottom:8px">' + esc(last.level_note) + "</div>" : "") +
      (last.summary_unbelegt ? '<div class="warnline">Zahlen in der Zusammenfassung, die nicht in den Daten stehen: ' + esc(last.summary_unbelegt.join(", ")) + "</div>" : "") +
      (find ? "<details><summary>Befunde (" + (last.findings || []).length + ")</summary>" + find + "</details>" : "") +
      '<div class="row sp" style="margin-top:10px"><span class="tiny">' + esc(last.model || "") + (last.ms ? " · " + Math.round(last.ms / 1000) + " s" : "") + (s.today ? " · " + esc(s.today.calls) + "/" + esc(s.today.cap) + " heute" : "") + '</span><button class="btn pri" data-act="analyze"' + (running ? " disabled" : "") + ">" + (running ? "Analysiere …" : "Jetzt analysieren") + "</button></div>";
    var w = waiting();
    slot("#wait").innerHTML = w.length ? '<div class="card warn"><h3>Wartet auf dich · ' + w.length + "</h3>" + w.map(function (p) {
      return '<div class="item prop"><b>' + esc(propTitle(p)) + '</b><div class="why">' + propWhy(p) + '</div><div class="row">' + (p.blocked_reason ? "" : '<button class="btn ok sm" data-act="prop-do" data-id="' + esc(p.id) + '">Ausführen …</button>') +
        '<button class="btn ghost sm" data-act="prop-no" data-id="' + esc(p.id) + '">Ablehnen</button></div></div>'; }).join("") + "</div>" : "";
    var facts = last.facts || [];
    slot("#factsCard").hidden = !facts.length;
    slot("#factsCard").innerHTML = "<h3>Fakten</h3><div class=\"facts\">" + facts.map(function (f) { return "<div><b>" + esc(f[0]) + "</b><span>" + esc(f[1]) + "</span></div>"; }).join("") + "</div>";
    var h = (s.history || []).slice(0, 12).reverse();
    slot("#pulseCard").hidden = !h.length;
    slot("#pulseCard").innerHTML = "<h3>Verlauf der letzten Analysen</h3><div class=\"pulse\">" + h.map(function (x, i) { return '<button class="' + (x.ok ? x.level === "alert" ? "alert" : x.level === "watch" ? "watch" : "" : "fail") + '" data-act="hist" data-i="' + i + '" aria-label="' + esc(clock(x.t) + " " + (LEVEL[x.level] ? LEVEL[x.level][0] : "Fehler")) + '"></button>'; }).join("") + "</div>";
    S.hist = h;
    if (lv === "alert" && !S.lastAlert && UI.vib && navigator.vibrate && document.visibilityState === "visible" && S.lastT) navigator.vibrate([200, 100, 200]);
    S.lastAlert = lv === "alert";
  }
  function setHud(cls, label, sub) { var h = $("#hud"); if (h) { h.className = "hud " + cls; h.innerHTML = "<b>" + esc(label) + "</b><small>" + esc(sub) + "</small>"; } }

  // ---------------------------------------------------------------- tasks
  function loadTasks() {
    return api("GET", "/api/tasks").then(function (j) { S.tasks = (j.result && j.result.tasks) || []; if (S.mounted === "tasks") updTasks(); scheduleTasks(); }).catch(function () { /* the next round tries again */ });
  }
  function scheduleTasks() {
    clearTimeout(S.tt); if (S.mounted !== "tasks") return;
    var busy = S.tasks.some(function (t) { return t.status === "queued" || t.status === "running"; });
    S.tt = setTimeout(loadTasks, busy ? 3000 : 20000);
  }
  function updTasks() {
    var el = $("#taskList"); if (!el) return; el = slotOf(el);
    el.innerHTML = "<h3>Deine Aufträge</h3>" + (S.tasks.length ? S.tasks.map(function (t) {
      var st2 = { queued: ["wartet", "vi"], running: ["läuft", "vi"], done: ["fertig", "ok"], error: ["Fehler", "bad"] }[t.status] || [t.status, ""];
      var acts = (t.actions || []).map(function (a) { return '<div class="row" style="margin:6px 0"><button class="btn ok sm" data-act="task-do" data-id="' + esc(a.id) + '" data-l="' + esc(a.label) + '"' + (a.blocked ? " disabled" : "") + ">" + esc(a.label) + "</button>" + (a.blocked ? '<span class="tiny">' + esc(a.blocked) + "</span>" : "") + "</div>"; }).join("");
      return '<div class="item"><div class="row sp"><span class="when">' + esc(dayClock(t.t)) + " · " + esc(t.who || "") + "</span>" + chip(st2[0], st2[1]) + '</div><div class="q">' + esc(t.text) + "</div>" +
        (t.answer ? '<div class="ans">' + esc(t.answer) + "</div>" : t.status === "queued" ? '<div class="tiny">Sie denkt darüber nach … das kann ein paar Minuten dauern.</div>' : "") +
        (t.error ? '<div class="warnline">' + esc(t.error) + "</div>" : "") + (t.unbelegt && t.unbelegt.length ? '<div class="warnline">Zahlen, die nicht in den Daten stehen: ' + esc(t.unbelegt.join(", ")) + "</div>" : "") + acts + "</div>";
    }).join("") : '<p class="muted">Noch keine Aufträge. Frag sie, was dich beschäftigt.</p>');
  }
  function sendTask() {
    var ta = $("#taskText"), text = ta.value.trim(); if (!text) { ta.focus(); return; }
    var b = $("[data-act=send-task]"); b.disabled = true;
    api("POST", "/api/task", { text: text }).then(function () { ta.value = ""; toast("Auftrag gesendet"); return loadTasks(); }).catch(function (e) { toast(errMsg(e), true); }).then(function () { b.disabled = false; });
  }
  function dictate() {
    var R = window.SpeechRecognition || window.webkitSpeechRecognition, mic = $("#mic"); if (!R) return;
    if (S.rec && mic.classList.contains("rec")) { S.rec.stop(); return; }
    var r = new R(); r.lang = "de-DE"; r.interimResults = false; r.maxAlternatives = 1; S.rec = r;
    r.onresult = function (e) { var t = e.results[0][0].transcript, ta = $("#taskText"); ta.value = (ta.value ? ta.value.replace(/\s*$/, " ") : "") + t; ta.focus(); };
    r.onerror = function (e) { toast(e.error === "not-allowed" ? "Mikrofon nicht erlaubt." : "Spracheingabe nicht möglich.", true); };
    r.onend = function () { mic.classList.remove("rec"); };
    mic.classList.add("rec"); try { r.start(); } catch (e) { mic.classList.remove("rec"); }
  }

  // ---------------------------------------------------------------- insight
  function updInsight() {
    $$("[data-act=seg]").forEach(function (b) { b.classList.toggle("on", b.dataset.t === S.insightTab); });
    var el = $("#insBody"); if (!el) return; el = slotOf(el);
    if (S.insightTab === "imp") {
      var imp = (st() && st().improve) || [];
      el.innerHTML = imp.length ? imp.map(function (x, i) {
        return '<div class="card ' + (x.prio === "hoch" ? "bad" : x.prio === "mittel" ? "warn" : "") + '"><div class="row sp"><b>' + esc(x.title) + "</b>" + chip(x.prio || "", x.prio === "hoch" ? "bad" : x.prio === "mittel" ? "warn" : "") + "</div><p class=\"muted\" style=\"margin-top:8px\">" + esc(x.text) + "</p>" +
          ((x.ex || []).length ? '<details><summary>Beispiele</summary>' + x.ex.map(function (e) { return '<div class="tiny">' + esc(e) + "</div>"; }).join("") + "</details>" : "") +
          (TASKS_ON ? '<div class="row" style="margin-top:8px"><button class="btn sm" data-act="imp-ask" data-i="' + i + '">Als Auftrag fragen</button></div>' : '') + '</div>'; }).join("") : '<div class="card ok"><p class="muted">Nichts zu verbessern. Das ist gut.</p></div>';
      return;
    }
    var inv = S.data && S.data.inv || { items: [] };
    var head = '<div class="card"><h3>Gerät untersuchen</h3><div class="row" style="flex-wrap:nowrap"><input id="invIp" type="text" inputmode="decimal" placeholder="IP-Adresse, z. B. 192.168.1.90" autocomplete="off" aria-label="IP-Adresse"><button class="btn pri" data-act="inv-now">Los</button></div>' +
      (inv.running ? '<p class="tiny" style="margin-top:8px">' + chip("läuft", "vi") + " " + esc(who(inv.running.ip)) + " · " + esc(inv.running.anlass) + "</p>" : "") +
      ((inv.queue || []).length ? '<p class="tiny">' + chip("wartet", "") + " " + esc(inv.queue.map(function (q) { return who(q.ip); }).join(", ")) + "</p>" : "") +
      '<p class="tiny" style="margin-top:8px">' + esc(inv.today || 0) + " von " + esc(inv.max_day || 6) + " Untersuchungen heute" + (inv.next ? " · als Nächstes: " + esc(inv.next) : "") + "</p></div>";
    var keep = $("#invIp") ? $("#invIp").value : "";
    el.innerHTML = head + (inv.items && inv.items.length ? inv.items.slice(0, 10).map(invItem).join("") : '<div class="card"><p class="muted">Noch keine Untersuchung. Sie startet von selbst bei einem belegten Anlass.</p></div>');
    if ($("#invIp")) $("#invIp").value = keep;
  }
  var VERD = { harmlos: ["HARMLOS", "ok"], unklar: ["UNKLAR", ""], verdaechtig: ["VERDÄCHTIG", "warn"], gefaehrlich: ["GEFÄHRLICH", "bad"] };
  var TNAME = { profil: "Verhaltensprofil", dns: "DNS-Anfragen", vorfaelle: "Vorfälle", suricata: "Suricata", umgehung: "DNS-Umgehung", weg: "Weg nach außen", menge: "Datenmengen" };
  var ANAME = { beobachten: "Beobachten", isolieren: "Isolieren", richtlinie: "Richtlinie durchsetzen", dns_haerten: "DNS härten", pruefen: "Selbst prüfen", nichts: "Nichts tun" };
  function invItem(it) {
    var v = VERD[it.urteil] || ["FEHLER", "bad"];
    var h = '<div class="card ' + (v[1] === "bad" ? "bad" : v[1] === "warn" ? "warn" : "") + '"><div class="row sp"><b>' + esc(it.name || it.ip) + "</b>" + chip(it.ok ? v[0] : "FEHLER", it.ok ? v[1] : "bad") + '</div><div class="tiny">' + esc(dayClock(it.t)) + " · " + esc(it.anlass) + "</div>";
    if (!it.ok) return h + '<div class="warnline">' + esc(it.error) + "</div></div>";
    h += '<p class="ans">' + esc(it.begruendung) + "</p>" + (it.unbelegt && it.unbelegt.length ? '<div class="warnline">Zahlen, die nicht in den Belegen stehen: ' + esc(it.unbelegt.join(", ")) + "</div>" : "");
    h += "<details><summary>Was sie sich angesehen hat</summary>" + (it.tools || []).map(function (t) { return '<div class="tiny"><b>' + esc(TNAME[t.name] || t.name) + "</b> " + esc(t.warum) + "</div>"; }).join("") + (it.belege || []).map(function (b) { return '<div class="tiny">· ' + esc(b) + "</div>"; }).join("") + "</details>";
    if ((it.plan || []).length) h += '<div class="plan">' + it.plan.map(function (p) {
      var tag = { vorschlag: ["VORSCHLAG", "warn"], empfehlung: ["EMPFEHLUNG", "cy"], verworfen: ["VERWORFEN", ""], info: ["NOTIZ", ""] }[p.status] || ["", ""];
      return "<div>" + chip(tag[0], tag[1]) + " <b>" + esc(ANAME[p.aktion] || p.aktion) + "</b> " + esc(p.warum) + (p.hinweis ? '<div class="tiny">' + esc(p.hinweis) + "</div>" : "") +
        (p.link && p.status === "vorschlag" ? '<div class="row" style="margin-top:6px"><button class="btn ok sm" data-act="inv-do" data-id="' + esc(p.link) + '" data-l="' + esc(ANAME[p.aktion] || p.aktion) + '">Ausführen …</button></div>' : "") + "</div>"; }).join("") + "</div>";
    return h + "</div>";
  }

  // ---------------------------------------------------------------- actions
  function updActions() {
    var s = st(); if (!s) return;
    var c = s.config || {};
    slot("#actTop").innerHTML = '<div class="card"><div class="row sp"><h3 style="margin:0">Autonomie</h3>' + chip(MODES[c.mode] || c.mode, c.mode === "auto" ? "warn" : "cy") + "</div><div class=\"facts\" style=\"margin-top:8px\">" +
      CAPS.map(function (k) { var v = c[k[0]]; return "<div><b style=\"grid-column:1\">" + esc(k[1]) + "</b><span>" + esc(CAPV[v] || v || "aus") + "</span></div>"; }).join("") + '</div><p class="tiny" style="margin-top:8px">Geändert wird das in der Firewall (Einstellungen › S.A.R.A.H.), nicht hier.</p></div>';
    var log = ((s.act && s.act.actions) || []).slice().sort(function (a, b) { return b.id - a.id; }).slice(0, 40);
    slot("#actLog").innerHTML = "<h3>Was sie getan hat</h3>" + (log.length ? log.map(function (e) {
      var probation = e.probation_until && !e.final && nowS() < e.probation_until;
      var res = e.result === "failed" ? chip("fehlgeschlagen", "bad") : e.result === "refused" ? chip("abgelehnt", "warn") : "";
      return '<div class="item"><div class="row sp"><span class="when">' + esc(dayClock(e.t)) + " · " + esc(e.who || "") + "</span><span>" + res + (e.final ? chip("dauerhaft", "ok") : probation ? chip("auf Probe bis " + new Date(e.probation_until * 1000).toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" }), "warn") : "") +
        '</span></div><div class="q">' + esc(ACT[e.type] || e.type) + "</div><div class=\"muted\">" + esc(e.descr || e.text || (e.ip ? who(e.ip) : "")) + (e.error ? " · " + esc(e.error) : "") + "</div>" +
        (e.active ? '<div class="row" style="margin-top:8px"><button class="btn sm ' + (probation ? "bad" : "") + '" data-act="release" data-id="' + esc(e.id) + '" data-l="' + esc((ACT[e.type] || e.type) + ": " + (e.descr || e.ip || "")) + '">' + (probation ? "Veto" : "Rückgängig") + "</button>" + (e.left ? '<span class="tiny">noch ' + Math.round(e.left / 60) + " min</span>" : "") + "</div>" : "") + "</div>";
    }).join("") : '<p class="muted">Noch nichts. Sie handelt nur, wenn du es erlaubt hast.</p>');
  }

  // ---------------------------------------------------------------- more: connection, notifications, app
  function pushSupported() { return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window && window.isSecureContext; }
  function refreshPush() {
    if (!pushSupported()) { S.push = { supported: false, secure: window.isSecureContext }; if (S.mounted === "more") updMore(); return; }
    navigator.serviceWorker.getRegistration().then(function (reg) { return reg ? reg.pushManager.getSubscription() : null; }).then(function (sub) {
      S.push = { supported: true, on: !!sub, perm: Notification.permission, endpoint: sub && sub.endpoint }; if (S.mounted === "more") updMore();
    }).catch(function () { S.push = { supported: true, on: false, perm: Notification.permission }; if (S.mounted === "more") updMore(); });
  }
  function u8(b64) { var p = "=".repeat((4 - b64.length % 4) % 4), s = atob((b64 + p).replace(/-/g, "+").replace(/_/g, "/")), a = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; }
  function pushOn() {
    return Notification.requestPermission().then(function (perm) {
      if (perm !== "granted") throw new ApiError("Benachrichtigungen sind für diese Seite blockiert. Erlaube sie in den Browser-Einstellungen.");
      return navigator.serviceWorker.ready;
    }).then(function (reg) {
      var opts = { userVisibleOnly: true, applicationServerKey: u8(S.data.push.key) };
      return reg.pushManager.getSubscription().then(function (old) { return old ? old.unsubscribe() : true; }).then(function () { return reg.pushManager.subscribe(opts); });
    }).then(function (sub) { return api("POST", "/api/push/subscribe", { subscription: sub.toJSON() }); });
  }
  function pushOff() {
    return navigator.serviceWorker.getRegistration().then(function (reg) { return reg ? reg.pushManager.getSubscription() : null; }).then(function (sub) {
      if (!sub) return null; var ep = sub.endpoint; return sub.unsubscribe().then(function () { return api("POST", "/api/push/unsubscribe", { endpoint: ep }); });
    });
  }
  function savePrefs(p) { return api("POST", "/api/prefs", p).then(function (j) { if (S.data) S.data.prefs = j; update(); }).catch(function (e) { toast(errMsg(e), true); update(); }); }
  function updMore() {
    var el = $("#moreBody"); if (!el || !S.data) { if (el) el.innerHTML = '<div class="card"><p class="muted">Lade …</p></div>'; return; }
    if (el.contains(document.activeElement) && /^(INPUT|SELECT)$/.test(document.activeElement.tagName) && document.activeElement.type !== "checkbox") return;   // do not pull a field out from under your finger
    var d = S.data, p = d.prefs, pn = d.pin, ps = S.push, h = d.health || {};
    var conn = (h.ok === false || d.stale) ? chip("offline", "bad") : chip("verbunden", "ok");
    var html = '<div class="card ' + (d.kind === "pin" ? "bad" : "") + '"><h3>Verbindung zur Firewall</h3><div class="row sp"><b class="mono">' + esc(d.host) + "</b>" + conn + "</div>" +
      (d.error ? '<p class="warnline" style="margin-top:8px">' + esc(d.error) + "</p>" : "") + '<p class="tiny" style="margin-top:8px">Letzter Kontakt ' + esc(ago(h.ok_t)) + " · Prüfung: " + (d.verify === "system" ? "Zertifikat der Zertifizierungsstelle" : "Fingerabdruck (selbst signiert)") + "</p>" +
      (pn ? '<pre class="fp">SHA-256 ' + esc(pn.fp) + "</pre><div class=\"tiny\">gemerkt seit " + esc(dayClock(pn.since)) + "</div>" : "") +
      (d.verify !== "system" ? '<div class="row" style="margin-top:10px"><button class="btn sm' + (d.kind === "pin" ? " bad" : "") + '" data-act="pin-trust">Zertifikat erneut bestätigen …</button></div>' : "") + "</div>";
    var tl = d.tls || {}, tlsBad = tl.error || (tl.on && tl.days_left < 14);
    html += '<div class="card' + (tlsBad ? " warn" : "") + '"><h3>HTTPS dieser App</h3>' + (tl.on ?
        '<div class="row sp"><b class="mono">' + esc((tl.names || []).join(", ")) + '</b><span class="chip ok">AN</span></div><p class="tiny" style="margin-top:6px">gültig bis ' + esc(String(tl.valid_to || "").slice(0, 10)) +
        " (" + esc(tl.days_left) + " Tage) · Aussteller " + esc(tl.issuer || "?") + " · " + esc(tl.file || "") + "</p>" :
        '<p class="tiny">Aus: kein Zertifikat in <span class="mono">/data/tls</span>. Mit einem Zertifikat aus deinem ACME-Client der OPNsense (Automatisierung „Upload certificate via SFTP“) spricht die App HTTPS - dann funktionieren Push und die Installation als App ohne Proxy. Anleitung im README.</p>') +
      (tl.error ? '<p class="warnline" style="margin-top:8px">' + esc(tl.error) + "</p>" : "") + (tl.on && tl.days_left < 14 ? '<p class="warnline" style="margin-top:8px">Läuft bald ab: erneuert der ACME-Client nicht mehr?</p>' : "") + "</div>";
    var pushHtml;
    if (!ps.supported) pushHtml = '<p class="warnline">' + (ps.secure === false ? "Push braucht eine sichere Verbindung (https). Öffne die App über deine https-Adresse." : "Dieser Browser kann keine Push-Meldungen empfangen. Auf iPhone/iPad: erst „Zum Home-Bildschirm“ hinzufügen.") + "</p>";
    else pushHtml = '<div class="row sp"><span>Auf diesem Gerät: ' + (ps.on ? chip("an", "ok") : chip("aus", "")) + '</span><span class="row">' + (ps.on ? '<button class="btn sm" data-act="push-test">Test</button><button class="btn sm ghost" data-act="push-off">Ausschalten</button>' : '<button class="btn sm pri" data-act="push-on">Einschalten</button>') + "</span></div>" +
      (ps.perm === "denied" ? '<p class="warnline">Im Browser blockiert. Erlaube Benachrichtigungen für diese Seite.</p>' : "") + '<p class="tiny" style="margin-top:6px">' + esc(d.push.devices) + " Gerät(e) angemeldet" + (d.push.ntfy ? " · ntfy aktiv" : "") + "</p>";
    html += '<div class="card"><h3>Benachrichtigungen</h3>' + pushHtml + '<p class="tiny" style="margin:10px 0 4px">Ein ruhiger Scan meldet sich nie.</p>' +
      '<div class="set"><span>Mindeststufe für einen Scan</span><div class="seg"><button data-act="lvl" data-l="watch" class="' + (p.level === "watch" ? "on" : "") + '">Beobachten</button><button data-act="lvl" data-l="alert" class="' + (p.level === "alert" ? "on" : "") + '">Alarm</button></div></div>' +
      EVENTS.map(function (e) { return '<div class="set"><span>' + esc(e[1]) + "<small>" + esc(e[2]) + '</small></span><label class="sw"><input type="checkbox" data-pref="' + e[0] + '"' + (p.events[e[0]] ? " checked" : "") + ' aria-label="' + esc(e[1]) + '"><i></i></label></div>'; }).join("") +
      '<div class="set"><span>Ruhezeiten<small>Nur ein Alarm kommt durch, der Rest als eine Sammelmeldung</small></span><label class="sw"><input type="checkbox" data-pref="quiet" ' + (p.quiet.on ? "checked" : "") + ' aria-label="Ruhezeiten"><i></i></label></div>' +
      (p.quiet.on ? '<div class="row" style="margin-top:8px"><input type="time" data-q="from" value="' + esc(p.quiet.from) + '" style="width:auto" aria-label="von"><span class="muted">bis</span><input type="time" data-q="to" value="' + esc(p.quiet.to) + '" style="width:auto" aria-label="bis"></div>' : "") + "</div>";
    html += '<div class="card"><h3>App</h3>' + (S.installEvt ? '<div class="set"><span>Auf dem Startbildschirm</span><button class="btn sm pri" data-act="install">Installieren</button></div>' : "") +
      '<div class="set"><span>Animation anhalten<small>Spart Akku</small></span><label class="sw"><input type="checkbox" data-ui="calm"' + (UI.calm ? " checked" : "") + ' aria-label="Animation anhalten"><i></i></label></div>' +
      '<div class="set"><span>Vibrieren bei Alarm<small>Wenn die App offen ist</small></span><label class="sw"><input type="checkbox" data-ui="vib"' + (UI.vib ? " checked" : "") + ' aria-label="Vibrieren bei Alarm"><i></i></label></div>' +
      '<div class="set"><span class="tiny">S.A.R.A.H. Companion ' + esc(d.version) + '</span><button class="btn sm ghost" data-act="logout">Abmelden</button></div></div>';
    html += anCard();
    setHtml(el, html);
  }

  // ---------------------------------------------------------------- refresh loop
  function refresh() {
    return api("GET", "/api/state").then(function (j) {
      S.data = j; S.err = null; S.cached = false; S.skew = j.now - Date.now() / 1000;
      try { localStorage.setItem("sarah.last", JSON.stringify({ t: j.now, data: j })); } catch (e) { /* too large or private mode */ }
      var s = j.status; if (S.busy.analyze && s && !s.running && s.last && s.last.t > S.analyzeFrom) { S.busy.analyze = false; toast("Analyse fertig: " + (LEVEL[s.last.level] ? LEVEL[s.last.level][0] : "")); }
      update();
    }).catch(function (e) { if (e.kind === "login") return; S.err = errMsg(e); update(); });
  }
  function tick() {
    clearTimeout(S.timer);
    if (!document.hidden) refresh();
    S.timer = setTimeout(tick, S.fastUntil > Date.now() ? 2000 : 6000);
  }
  function stopTimers() { clearTimeout(S.timer); clearTimeout(S.tt); }
  document.addEventListener("visibilitychange", function () { if (S.me && !document.hidden) { tick(); if (S.mounted === "tasks") loadTasks(); } });

  // ---------------------------------------------------------------- clicks
  /* ---- Vorfälle: the same incidents and the same work on them as on the DECK page of the firewall */
  var SRCN = { radar: "Radar", suricata: "Suricata", dns: "DNS", lernmodus: "Lernmodus", fernzugriff: "Fernzugriff", tls: "TLS", beacon: "Beaconing", l7: "Anwendungen", dnstunnel: "DNS-Tunnel",
    intel: "Threat-Intel", zenarmor: "Zenarmor", lan: "LAN-Wächter" };
  var CASEN = [["new", "Neu"], ["progress", "In Bearbeitung"], ["done", "Erledigt"], ["false", "Fehlalarm"]];
  var INC = { d: null, tab: "live", open: null, t: 0, timer: null };
  function loadIncidents() {
    return api("GET", "/api/incidents").then(function (j) { INC.d = j.result || {}; INC.t = nowS(); if (S.mounted === "incidents") updIncidents(); })
      .catch(function (e) { slot("#incBody").innerHTML = '<div class="card bad"><h3>Vorfälle nicht abrufbar</h3><p>' + esc(errMsg(e)) + "</p></div>"; })
      .then(function () { clearTimeout(INC.timer); if (S.mounted === "incidents") INC.timer = setTimeout(loadIncidents, 60000); });
  }
  function incState(i) { return i.state === "open" ? ["OFFEN", "bad"] : i.state === "done" ? ["ERLEDIGT", "ok"] : ["BEOBACHTEN", "warn"]; }
  function updIncidents() {
    $$("[data-act=iseg]").forEach(function (b) { b.classList.toggle("on", b.dataset.t === INC.tab); });
    var d = INC.d || {}, L = (d.incidents || []).filter(function (i) { return INC.tab === "done" ? i.state === "done" : i.state !== "done"; }), k = d.kpi || {};
    slot("#incTs").innerHTML = INC.t ? " Stand " + clock(INC.t) : "";
    if (!L.length) { slot("#incBody").innerHTML = '<div class="card ok"><h3>' + (INC.tab === "done" ? "Nichts erledigt" : "Keine Vorfälle") + "</h3><p>" + (INC.tab === "done" ? "In den letzten 24 Stunden wurde kein Vorfall erledigt." : "In den letzten 24 Stunden fällt kein Gerät in mehreren Quellen zugleich auf.") + "</p></div>"; return; }
    var head = INC.tab === "live" ? '<div class="facts" style="margin-bottom:12px"><div><b>Offen</b><span>' + (k.open || 0) + "</span></div><div><b>Beobachtet</b><span>" + (k.watch || 0) + "</span></div><div><b>Höchster Wert</b><span>" + (k.max || 0) + "/100</span></div></div>" : "";
    slot("#incBody").innerHTML = head + L.map(function (i) {
      var s = incState(i), c = i.case || {}, open = INC.open === i.id;
      var h = '<div class="card ' + s[1] + '" data-inc="' + esc(i.id) + '"><div class="row" data-act="inc-open" data-id="' + esc(i.id) + '" style="cursor:pointer"><b style="font-size:20px;min-width:52px">' + i.score + '</b><div style="flex:1"><b>' + esc(who(i.ip)) + '</b><div class="tiny">seit ' + dayClock(i.start) + " · " + i.signals.length + (i.more ? "+" : "") + " Indizien</div></div>" + chip(s[0], s[1]) + "</div>" +
        '<div style="margin-top:8px">' + i.sources.map(function (x) { return chip(SRCN[x] || x, "cy"); }).join(" ") + (c.status && c.status !== "new" ? " " + chip((CASEN.filter(function (z) { return z[0] === c.status; })[0] || [0, c.status])[1], "vi") : "") + "</div>";
      if (open) {
        h += '<h3 style="margin-top:14px">Zeitverlauf</h3>' + i.signals.map(function (x) { return '<div class="item"><span class="tiny">' + clock(x.t) + " · " + esc(SRCN[x.src] || x.src) + "</span><b>" + esc(x.title) + '</b><div class="tiny">' + esc(x.detail || "") + "</div></div>"; }).join("") +
          "<h3>Warum dieser Wert?</h3>" + i.contrib.map(function (x) { return '<div class="row tiny"><span style="flex:1">' + esc(SRCN[x.src] || x.src) + "</span><b>+" + x.pts + "</b></div>"; }).join("") + (i.ctx ? '<div class="row tiny"><span style="flex:1">Neues Gerät</span><b>+' + i.ctx + "</b></div>" : "") +
          '<h3>Bearbeitung</h3><div class="seg" style="flex-wrap:wrap">' + CASEN.map(function (z) { return '<button data-act="inc-case" data-ip="' + esc(i.ip) + '" data-st="' + z[0] + '" data-until="' + i.ack_until + '" class="' + ((c.status || "new") === z[0] ? "on" : "") + '">' + z[1] + "</button>"; }).join("") + "</div>" +
          (c.by ? '<div class="tiny" style="margin-top:6px">zuletzt: ' + esc(c.by === "du" ? "Du" : c.by) + " · " + ago(c.at) + "</div>" : "") +
          (c.status === "false" ? '<p class="tiny">Als Fehlalarm markiert: die beteiligten Quellen zählen bei diesem Gerät künftig weniger.</p>' : "") +
          "<h3>S.A.R.A.H.</h3>" + incSarah(i) +
          "<h3>Notizen</h3>" + (c.notes || []).map(function (n) { return '<div class="item"><span class="tiny">' + dayClock(n.t) + " · " + esc(n.who === "du" ? "Du" : n.who) + "</span><div>" + esc(n.text) + "</div></div>"; }).join("") +
          '<textarea id="incNote" maxlength="1000" rows="2" placeholder="Notiz zum Vorfall …"></textarea><div class="row" style="margin-top:8px"><button class="btn sm" data-act="inc-note" data-ip="' + esc(i.ip) + '">Notiz speichern</button></div>';
      }
      return h + "</div>";
    }).join("");
  }
  function incSarah(i) {
    var s = (i.case || {}).sarah || {};
    if (s.pending) return '<p class="muted">Untersucht gerade …</p>';
    if (s.item) {
      var it = s.item;
      return "<p><b>" + esc(it.urteil || "") + "</b> " + esc(it.begruendung || "") + "</p>" + (it.plan || []).map(function (p) {
        return '<div class="item"><b>' + esc(p.aktion) + '</b><div class="tiny">' + esc(p.warum || "") + "</div>" + (p.status === "vorschlag" && p.link ? '<button class="btn ok sm" data-act="inv-do" data-id="' + esc(p.link) + '" data-l="' + esc(p.aktion) + '">Ausführen …</button>' : "") + "</div>"; }).join("");
    }
    return '<p class="muted">Sie untersucht das Gerät mit diesem Vorfall als Anlass (nur lesend) und schlägt vor, was zu tun ist. Ausgeführt wird nur, was du bestätigst.</p><button class="btn sm" data-act="inc-hand" data-ip="' + esc(i.ip) + '">An S.A.R.A.H. übergeben</button>';
  }
  /* ---- Analyzer: the firewall's logs arrive here (os-scdeck 0.60+, DECK › Einstellungen › Analyzer) */
  function loadAn() { api("GET", "/api/analyzer").then(function (j) { S.an = j; if (S.mounted === "more") updMore(); }).catch(function () { /* shown as missing */ }); }
  function anCard() {
    var a = S.an; if (!a) return "";
    if (a.off) return '<div class="card"><h3>Analyzer</h3><p class="tiny">Aus (ANALYZER_PORT=0).</p></div>';
    var c = a.counters || {}, e = (a.tables || {}).eve || {}, sy = (a.tables || {}).sys || {}, gb = function (b) { return (b / 1073741824).toFixed(b > 1073741824 ? 1 : 2) + " GB"; };
    var live = c.last && nowS() - c.last < 300;
    return '<div class="card' + (c.refused && !c.received ? " warn" : "") + '"><h3>Analyzer · Protokolle der Firewall</h3><div class="row sp"><b class="mono">Port ' + esc(a.port) + " · " + (a.tls ? "TLS" : "TCP") + "</b>" + (live ? chip("empfängt", "ok") : chip(c.received ? "ruhig" : "wartet", c.received ? "" : "warn")) + "</div>" +
      '<div class="facts" style="margin-top:10px"><div><b>Suricata</b><span>' + (e.rows || 0).toLocaleString("de-DE") + '</span></div><div><b>System</b><span>' + (sy.rows || 0).toLocaleString("de-DE") + '</span></div><div><b>Speicher</b><span>' + gb(a.bytes || 0) + " / " + esc(a.max_gb) + ' GB</span></div><div><b>Aufbewahrung</b><span>' + esc(a.days) + " Tage</span></div></div>" +
      '<p class="tiny" style="margin-top:8px">Empfangen ' + (c.received || 0) + " · geschrieben " + (c.written || 0) + " · verworfen " + ((c.dropped_queue || 0) + (c.dropped_long || 0)) + " · unlesbar " + (c.bad || 0) + " · abgewiesen " + (c.refused || 0) + " · zuletzt " + esc(c.last ? ago(c.last) : "nie") + "</p>" +
      '<p class="tiny">Erlaubte Absender: ' + esc((a.allow || []).join(", ") || "keiner") + "</p>" +
      (a.cert ? '<details><summary>Zertifikat für die Firewall (DECK › Einstellungen › Analyzer)</summary><pre class="fp">' + esc(a.cert) + '</pre><div class="tiny">SHA-256 ' + esc(a.cert_sha256) + "</div></details>" : "") + "</div>";
  }
  /* ---- Monitor: the firewall's logs in the Analyzer, like the Monitor tab of Panorama / Log View of FortiAnalyzer.
     Four log types, time range, text search, field filters (a value in the table is a filter with one tap, "!" excludes), overview with
     the course over time and top lists, detail of an entry, CSV with the same filters. Everything is filtered on the server. */
  var LT = [["threat", "Bedrohungen"], ["app", "Anwendungen"], ["traffic", "Firewall"], ["system", "System"]];
  var LCOLS = {
    threat: [["t", "Zeit"], ["sev", "Schwere"], ["action", "Aktion"], ["src", "Quelle"], ["dst", "Ziel"], ["dport", "Port"], ["sig", "Signatur"]],
    app: [["t", "Zeit"], ["type", "Art"], ["src", "Gerät"], ["host", "Name"], ["dst", "Ziel"], ["dport", "Port"], ["version", "TLS"]],
    traffic: [["t", "Zeit"], ["action", "Aktion"], ["dir", "Richtung"], ["iface", "Schnittstelle"], ["proto", "Protokoll"], ["src", "Quelle"], ["dst", "Ziel"], ["dport", "Port"], ["rid", "Regel"]],
    system: [["t", "Zeit"], ["program", "Programm"], ["msg", "Meldung"]]
  };
  var LF = { src: "Quelle", dst: "Ziel", port: "Port", action: "Aktion", sev: "Schwere", proto: "Protokoll", iface: "Schnittstelle", host: "Name", rid: "Regel", program: "Programm", sig: "Signatur", type: "Art", dir: "Richtung", version: "TLS", q: "Text" };
  var FILTERABLE = { sev: 1, action: 1, src: 1, dst: 1, dport: "port", sport: "port", sig: 1, host: 1, type: 1, dir: 1, iface: 1, proto: 1, rid: 1, program: 1, version: 1 };
  var RANGES = [[3600, "1 h"], [86400, "24 h"], [7 * 86400, "7 Tage"], [30 * 86400, "30 Tage"]];
  var MON = { kind: "threat", range: 86400, f: {}, rows: [], total: 0, offset: 0, sum: null, counts: {}, rules: {}, live: true, timer: null, busy: false };
  (function () { try { var x = JSON.parse(localStorage.getItem("sarah.mon") || "{}"); if (x.kind) MON.kind = x.kind; if (x.range) MON.range = x.range; } catch (e) { /* private mode */ } })();
  function monSave() { try { localStorage.setItem("sarah.mon", JSON.stringify({ kind: MON.kind, range: MON.range })); } catch (e) { /* private mode */ } }
  function monQuery(extra) {
    var p = { from: Math.floor(nowS() - MON.range) }; Object.keys(MON.f).forEach(function (k) { p[k] = MON.f[k]; });
    Object.keys(extra || {}).forEach(function (k) { p[k] = extra[k]; });
    return Object.keys(p).map(function (k) { return encodeURIComponent(k) + "=" + encodeURIComponent(p[k]); }).join("&");
  }
  function monLoad(more) {
    if (MON.busy) return; MON.busy = true;
    var off = more ? MON.rows.length : 0, base = "/api/logs/" + MON.kind;
    var jobs = [api("GET", base + "?" + monQuery({ offset: off, limit: 100 }))];
    if (!more) jobs.push(api("GET", base + "/summary?" + monQuery()), api("GET", "/api/logs/counts"));
    Promise.all(jobs).then(function (r) {
      MON.rows = more ? MON.rows.concat(r[0].rows) : r[0].rows; MON.total = r[0].total; MON.err = null;
      if (!more) { MON.sum = r[1]; MON.counts = r[2]; }
    }).catch(function (e) { MON.err = errMsg(e); }).then(function () { MON.busy = false; if (S.mounted === "monitor") updMonitor(); monTimer(); });
  }
  function monTimer() { clearTimeout(MON.timer); if (S.mounted === "monitor" && MON.live && MON.rows.length <= 100) MON.timer = setTimeout(function () { monLoad(false); }, 30000); }
  function monCell(k, r) {
    var v = r[k];
    if (v == null || v === "") return '<span class="tiny">–</span>';
    var shown;
    if (k === "t") return '<span class="mono">' + dayClock(v) + "</span>";
    if (k === "sev") shown = chip({ 1: "kritisch", 2: "hoch", 3: "mittel", 4: "niedrig" }[v] || v, { 1: "bad", 2: "warn", 3: "", 4: "" }[v]);
    else if (k === "action") shown = chip(v, /block|drop|reject/.test(v) ? "ok" : v === "allowed" ? "bad" : "");
    else if (k === "src" || k === "dst") shown = esc(S.data && S.data.status && S.data.status.names && S.data.status.names[v] ? S.data.status.names[v] + " (" + v + ")" : v);
    else if (k === "rid") shown = esc(MON.rules[v] || String(v).slice(0, 8) + "…");
    else shown = esc(v);
    var f = FILTERABLE[k]; if (!f) return shown;
    return '<button class="lv" data-act="mon-f" data-k="' + (f === "port" ? "port" : k) + '" data-v="' + esc(v) + '" title="Als Filter">' + shown + "</button>";
  }
  function updMonitor() {
    var el = $("#monBody"); if (!el) return;
    var cols = LCOLS[MON.kind], s = MON.sum || { hist: [], top: {} };
    $$("[data-act=mon-kind]").forEach(function (b) { b.classList.toggle("on", b.dataset.k === MON.kind); var c = MON.counts[b.dataset.k]; b.querySelector("i").textContent = c != null ? c.toLocaleString("de-DE") : ""; });
    $$("[data-act=mon-range]").forEach(function (b) { b.classList.toggle("on", +b.dataset.r === MON.range); });
    $("#monLive").classList.toggle("on", MON.live);
    var chips = Object.keys(MON.f).map(function (k) { return '<button class="chip cy fchip" data-act="mon-unf" data-k="' + k + '">' + esc(LF[k] || k) + (MON.f[k].charAt(0) === "!" ? " ≠ " + esc(MON.f[k].slice(1)) : ": " + esc(MON.f[k])) + " ✕</button>"; }).join(" ");
    slot("#monChips").innerHTML = chips ? chips + ' <button class="chip" data-act="mon-clear">Alle Filter weg</button>' : '<span class="tiny">Kein Filter. Tippe auf einen Wert in der Tabelle, um danach zu filtern.</span>';
    var mx = Math.max.apply(null, s.hist.map(function (h) { return h.n; }).concat([1]));
    var top = Object.keys(s.top || {}).map(function (k) {
      var L = s.top[k] || []; if (!L.length) return "";
      var m = Math.max.apply(null, L.map(function (x) { return x.n; }).concat([1])), fk = FILTERABLE[k] === "port" ? "port" : k;
      return '<div class="card topl"><h3>' + esc({ src: "Häufigste Quellen", dst: "Häufigste Ziele", sig: "Häufigste Signaturen", host: "Häufigste Namen", dport: "Häufigste Ports", rid: "Häufigste Regeln", program: "Programme", action: "Aktion", sev: "Schwere" }[k] || k) + "</h3>" +
        L.map(function (x) { var lab = k === "rid" ? (MON.rules[x.v] || String(x.v).slice(0, 8) + "…") : k === "sev" ? ({ 1: "kritisch", 2: "hoch", 3: "mittel", 4: "niedrig" }[x.v] || x.v) : (k === "src" || k === "dst") && S.data && S.data.status && S.data.status.names && S.data.status.names[x.v] ? S.data.status.names[x.v] : x.v;
          return '<div class="tb" role="button" tabindex="0" data-act="mon-f" data-k="' + fk + '" data-v="' + esc(x.v) + '"><span>' + esc(lab) + '</span><i style="width:' + Math.round(x.n / m * 100) + '%"></i><b>' + x.n.toLocaleString("de-DE") + "</b></div>"; }).join("") + "</div>";
    }).join("");
    var head = "<tr>" + cols.map(function (c) { return "<th>" + esc(c[1]) + "</th>"; }).join("") + "<th></th></tr>";
    var body = MON.rows.map(function (r) { return "<tr>" + cols.map(function (c) { return '<td data-c="' + c[0] + '">' + monCell(c[0], r) + "</td>"; }).join("") + '<td><button class="btn sm ghost" data-act="mon-row" data-id="' + r.id + '" aria-label="Details">›</button></td></tr>'; }).join("");
    el.innerHTML = (MON.err ? '<div class="card bad"><h3>Abfrage nicht möglich</h3><p>' + esc(MON.err) + "</p></div>" : "") +
      '<div class="card"><div class="row sp"><h3 style="margin:0">' + MON.total.toLocaleString("de-DE") + " Einträge · " + esc((RANGES.filter(function (x) { return x[0] === MON.range; })[0] || [0, ""])[1]) + '</h3><span class="tiny">je Balken ' + Math.round((s.step || 60) / 60) + ' min</span></div><div class="hist">' +
      s.hist.map(function (h) { return '<i style="height:' + Math.max(2, Math.round(h.n / mx * 100)) + '%" title="' + esc(dayClock(h.b) + " · " + h.n) + '"></i>'; }).join("") + "</div></div>" +
      '<div class="tops">' + top + "</div>" +
      (MON.rows.length ? '<div class="card logs"><table class="lt">' + head + body + "</table></div>" : '<div class="card"><p class="muted">Keine Einträge für diesen Filter und Zeitraum.</p></div>') +
      (MON.rows.length < MON.total ? '<div class="row" style="justify-content:center"><button class="btn sm" data-act="mon-more">Ältere laden (' + (MON.total - MON.rows.length).toLocaleString("de-DE") + ")</button></div>" : "");
    $("#monCsv").href = "/api/logs/" + MON.kind + "/csv?" + monQuery();
  }
  function monDetail(id) {
    api("GET", "/api/logs/" + MON.kind + "/entry/" + encodeURIComponent(id)).then(function (d) {
      var pretty = d.raw; try { pretty = JSON.stringify(JSON.parse(d.raw), null, 2); } catch (e) { /* plain text */ }
      var rows = Object.keys(d).filter(function (k) { return k !== "raw" && d[k] != null && d[k] !== ""; }).map(function (k) {
        var f = FILTERABLE[k], key = f === "port" ? "port" : k;
        return "<div><b>" + esc(LF[k] || k) + "</b><span>" + (k === "t" ? esc(dayClock(d[k])) : esc(k === "rid" ? (MON.rules[d[k]] || d[k]) : d[k])) +
          (f ? ' <button class="chip cy" data-act="mon-f" data-k="' + key + '" data-v="' + esc(d[k]) + '">nur das</button> <button class="chip" data-act="mon-f" data-k="' + key + '" data-v="!' + esc(d[k]) + '">ohne</button>' : "") + "</span></div>";
      }).join("");
      sheet({ title: "Eintrag", html: '<div class="facts">' + rows + '</div><details><summary class="tiny">Rohdaten</summary><pre class="fp raw">' + esc(pretty) + "</pre></details>", cancel: "Schließen" });
    }).catch(function (e) { toast(errMsg(e), true); });
  }
  function monSearch(v) { if (v) MON.f.q = v; else delete MON.f.q; monLoad(false); }
  function doThen(label, p, after) { return p.then(function () { toast(label); return refresh(); }).then(after || function () { }).catch(function (e) { toast(errMsg(e), true); }); }
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-act]"); if (!b || !S.me && b.dataset.act !== "sheet-close") return;
    var a = b.dataset.act;
    if (a === "sheet-close") { if (e.target === b || b.classList.contains("btn")) closeSheet(); return; }
    if (a === "sheet-ok") { var o = S.sheet, f = $("#shF"), v = f ? f.value : ""; closeSheet(); if (o && o.onOk) o.onOk(v); return; }
    if (a === "go") { location.hash = "#" + b.dataset.v; return; }
    if (a === "refresh") { refresh().then(function () { toast("Aktualisiert"); }); if (S.mounted === "tasks") loadTasks(); return; }
    if (a === "analyze") { S.busy.analyze = true; S.analyzeFrom = (st() && st().last && st().last.t) || 0; S.fastUntil = Date.now() + 240000; update(); api("POST", "/api/analyze").then(function () { toast("Analyse gestartet"); tick(); }).catch(function (x) { S.busy.analyze = false; toast(errMsg(x), true); update(); }); return; }
    if (a === "hist") { var x = S.hist && S.hist[+b.dataset.i]; if (x) sheet({ title: (LEVEL[x.level] ? LEVEL[x.level][0] : "Fehler") + " · " + dayClock(x.t), html: "<p>" + esc(x.summary) + '</p><p class="tiny">' + esc(x.model || "") + " · " + Math.round((x.ms || 0) / 1000) + " s · Anlass: " + esc(x.why || "") + "</p>" }); return; }
    if (a === "prop-do" || a === "task-do" || a === "inv-do") {
      var id = b.dataset.id, p = waiting().filter(function (q) { return q.id === id; })[0], title = p ? propTitle(p) : (b.dataset.l || id);
      sheet({ title: "Ausführen?", html: "<p><b>" + esc(title) + "</b></p><p class=\"muted\">S.A.R.A.H. prüft vor der Ausführung alles noch einmal und baut zurück, wenn etwas nicht stimmt. Eine Woche lang kannst du ein Veto einlegen.</p>", ok: "Jetzt ausführen",
        onOk: function () { doThen("Ausgeführt", api("POST", "/api/do", { id: id }), function () { if (S.mounted === "tasks") loadTasks(); }); } }); return;
    }
    if (a === "prop-no") { var id2 = b.dataset.id; doThen("Abgelehnt", api("POST", "/api/dismiss", { id: id2 })); return; }
    if (a === "send-task") { sendTask(); return; }
    if (a === "chip") { var c = CHIPS[+b.dataset.i], ta = $("#taskText"); ta.value = c; ta.focus(); ta.setSelectionRange(c.length, c.length); return; }
    if (a === "mic") { dictate(); return; }
    if (a === "seg") { S.insightTab = b.dataset.t; updInsight(); return; }
    if (a === "mon-kind") { MON.kind = b.dataset.k; MON.f = MON.f.q ? { q: MON.f.q } : {}; monSave(); monLoad(false); return; }
    if (a === "mon-range") { MON.range = +b.dataset.r; monSave(); monLoad(false); return; }
    if (a === "mon-f") { MON.f[b.dataset.k] = b.dataset.v; if (S.sheet) closeSheet(); monLoad(false); return; }
    if (a === "mon-unf") { delete MON.f[b.dataset.k]; if (b.dataset.k === "q") $("#monQ").value = ""; monLoad(false); return; }
    if (a === "mon-clear") { MON.f = {}; $("#monQ").value = ""; monLoad(false); return; }
    if (a === "mon-more") { monLoad(true); return; }
    if (a === "mon-live") { MON.live = !MON.live; updMonitor(); monTimer(); return; }
    if (a === "mon-row") { monDetail(b.dataset.id); return; }
    if (a === "iseg") { INC.tab = b.dataset.t; INC.open = null; updIncidents(); return; }
    if (a === "inc-open") { INC.open = INC.open === b.dataset.id ? null : b.dataset.id; updIncidents(); return; }
    if (a === "inc-case") { doThen("Gespeichert", api("POST", "/api/incident/case", { ip: b.dataset.ip, status: b.dataset.st, until: +b.dataset.until }), loadIncidents); return; }
    if (a === "inc-hand") { b.disabled = true; doThen("An S.A.R.A.H. übergeben", api("POST", "/api/incident/handover", { ip: b.dataset.ip }), loadIncidents); return; }
    if (a === "inc-note") { var nt = ($("#incNote") || {}).value || ""; if (!nt.trim()) return; doThen("Notiz gespeichert", api("POST", "/api/incident/note", { ip: b.dataset.ip, text: nt.trim() }), loadIncidents); return; }
    if (a === "inv-now") { var ip = $("#invIp").value.trim(); if (!ip) { $("#invIp").focus(); return; } doThen("Untersuchung eingeplant", api("POST", "/api/inv/now", { ip: ip }), function () { $("#invIp").value = ""; S.fastUntil = Date.now() + 300000; }); return; }
    if (a === "imp-ask") { var im = st().improve[+b.dataset.i]; location.hash = "#tasks"; setTimeout(function () { var t2 = $("#taskText"); if (t2) { t2.value = "Erkläre mir und prüfe: " + im.title; t2.focus(); } }, 50); return; }
    if (a === "release") { var rid = b.dataset.id; sheet({ title: b.textContent.trim() === "Veto" ? "Veto einlegen?" : "Rückgängig machen?", html: "<p><b>" + esc(b.dataset.l) + "</b></p><p class=\"muted\">Die Änderung wird zurückgenommen.</p>", ok: "Ja, zurücknehmen", danger: true,
      onOk: function () { doThen("Zurückgenommen", api("POST", "/api/release", { id: rid })); } }); return; }
    if (a === "noaus") { sheet({ title: "Not-Aus", html: "<p>Alle aktiven Eingriffe werden aufgehoben und alle Fähigkeiten ausgeschaltet.</p><p class=\"muted\">Zur Bestätigung tippe <b>NOT-AUS</b>.</p>", field: { placeholder: "NOT-AUS", valid: function (v) { return v.trim().toUpperCase() === "NOT-AUS"; } }, ok: "Not-Aus auslösen", danger: true,
      onOk: function () { doThen("Not-Aus ausgelöst", api("POST", "/api/noaus", { confirm: true })); } }); return; }
    if (a === "pin-trust") { sheet({ title: "Zertifikat bestätigen", html: "<p>Der Companion vertraut ab jetzt dem Zertifikat, das die Firewall <b>gerade</b> zeigt. Tu das nur, wenn du es selbst geändert hast (z. B. neu installiert oder Zertifikat erneuert).</p><p class=\"muted\">Zur Bestätigung dein Passwort:</p>", field: { type: "password", placeholder: "Passwort", valid: function (v) { return v.length >= 8; } }, ok: "Vertrauen", danger: true,
      onOk: function (pw) { doThen("Zertifikat bestätigt", api("POST", "/api/pin/trust", { password: pw })); } }); return; }
    if (a === "push-on") { pushOn().then(function () { toast("Meldungen sind an"); return refresh(); }).then(refreshPush).catch(function (x) { toast(errMsg(x), true); refreshPush(); }); return; }
    if (a === "push-off") { pushOff().then(function () { toast("Meldungen sind aus"); return refresh(); }).then(refreshPush).catch(function (x) { toast(errMsg(x), true); }); return; }
    if (a === "push-test") { api("POST", "/api/push/test").then(function (j) { toast(j.sent ? "Test gesendet" : "Kein Gerät hat es erhalten" + (j.errors && j.errors.length ? " (" + j.errors[0] + ")" : ""), !j.sent); }).catch(function (x) { toast(errMsg(x), true); }); return; }
    if (a === "lvl") { savePrefs({ level: b.dataset.l }); return; }
    if (a === "install") { var ev = S.installEvt; S.installEvt = null; ev.prompt(); updMore(); return; }
    if (a === "logout") { api("POST", "/api/logout").then(function () { location.reload(); }); return; }
  });
  document.addEventListener("change", function (e) {
    var t = e.target;
    if (t.dataset.pref === "quiet") { savePrefs({ quiet: { on: t.checked } }); }
    else if (t.dataset.pref) { var ev = {}; ev[t.dataset.pref] = t.checked; savePrefs({ events: ev }); }
    else if (t.dataset.q) { var q = {}; q[t.dataset.q] = t.value; savePrefs({ quiet: q }); }
    else if (t.dataset.ui) { UI[t.dataset.ui] = t.checked; saveUi(); if (t.dataset.ui === "calm" && S.core) S.core.pause(UI.calm); }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey) && e.target.id === "taskText") sendTask();
    if (e.key === "Enter" && e.target.id === "invIp") { var b = $("[data-act=inv-now]"); if (b) b.click(); }
  });
  window.addEventListener("beforeinstallprompt", function (e) { e.preventDefault(); S.installEvt = e; if (S.mounted === "more") updMore(); });

  // ---------------------------------------------------------------- start
  function start() {
    shell();
    try { var c = JSON.parse(localStorage.getItem("sarah.last") || "null"); if (c && c.data) { S.data = c.data; S.cached = true; S.skew = c.data.now - Date.now() / 1000; } } catch (e) { /* no cache */ }
    route(); tick();
  }
  function boot() {
    if ("serviceWorker" in navigator && window.isSecureContext) navigator.serviceWorker.register("/sw.js").catch(function () { /* the app works without it */ });
    api("GET", "/api/me").then(function (j) { S.me = j.login; if (S.me) start(); else showLogin(); }).catch(function () {
      var cached = null; try { cached = JSON.parse(localStorage.getItem("sarah.last") || "null"); } catch (e) { /* none */ }
      if (cached && cached.data) { S.me = true; start(); S.err = "Du bist offline."; update(); return; }     // offline start: show the last known state instead of an error page
      document.body.innerHTML = '<div class="login"><h1>S.A.R.A.H.</h1><p class="err">Der Companion ist nicht erreichbar.</p><button class="btn" onclick="location.reload()">Erneut versuchen</button></div>';
    });
  }
  boot();
})();
