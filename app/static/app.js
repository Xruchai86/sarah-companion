/* S.A.R.A.H. Companion - the app. No framework, no external resources. Every text that comes from the firewall or from the language model is
   untrusted: it only ever enters the page through esc() (or textContent). */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

  var VIEWS = [["core", "Kern"], ["tasks", "Aufträge"], ["insight", "Befunde"], ["actions", "Aktionen"], ["more", "Mehr"]];
  var ICON = {
    core: '<circle cx="12" cy="12" r="3"/><circle cx="12" cy="12" r="9"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>',
    tasks: '<path d="M4 5h16v11H9l-5 4z"/>', insight: '<circle cx="11" cy="11" r="6"/><path d="M16 16l5 5"/>',
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
    if (v === "more") refreshPush();
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
          '<div class="row" style="margin-top:8px"><button class="btn sm" data-act="imp-ask" data-i="' + i + '">Als Auftrag fragen</button></div></div>'; }).join("") : '<div class="card ok"><p class="muted">Nichts zu verbessern. Das ist gut.</p></div>';
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
