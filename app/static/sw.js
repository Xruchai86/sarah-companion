/* S.A.R.A.H. Companion - service worker: opens offline (the app shell), shows push messages, and takes you to the right page when you tap one.
   It never caches /api: what the firewall says is always asked fresh. */
var V = "sarah-v1", SHELL = ["/", "/app.css", "/app.js", "/sarah.js", "/manifest.webmanifest", "/icon-192.png"];
self.addEventListener("install", function (e) { e.waitUntil(caches.open(V).then(function (c) { return c.addAll(SHELL); }).then(function () { return self.skipWaiting(); })); });
self.addEventListener("activate", function (e) {
  e.waitUntil(caches.keys().then(function (ks) { return Promise.all(ks.filter(function (k) { return k !== V; }).map(function (k) { return caches.delete(k); })); }).then(function () { return self.clients.claim(); }));
});
self.addEventListener("fetch", function (e) {
  var r = e.request, u = new URL(r.url);
  if (r.method !== "GET" || u.origin !== location.origin || u.pathname.indexOf("/api/") === 0 || u.pathname === "/healthz") return;
  e.respondWith(fetch(r).then(function (res) { if (res.ok) { var c = res.clone(); caches.open(V).then(function (ch) { ch.put(r, c); }); } return res; }).catch(function () { return caches.match(r).then(function (m) { return m || caches.match("/"); }); }));
});
self.addEventListener("push", function (e) {
  var d = {}; try { d = e.data ? e.data.json() : {}; } catch (x) { d = { title: "S.A.R.A.H.", body: e.data ? e.data.text() : "" }; }
  var alert = d.level === "alert";
  e.waitUntil(self.registration.showNotification(d.title || "S.A.R.A.H.", {
    body: d.body || "", tag: d.tag || "sarah", renotify: alert, requireInteraction: alert, icon: "/icon-192.png", badge: "/badge-96.png", timestamp: (d.t || Date.now() / 1000) * 1000,
    vibrate: alert ? [300, 120, 300, 120, 300] : [120], data: { tab: d.tab || "core" }
  }));
});
self.addEventListener("notificationclick", function (e) {
  e.notification.close();
  var tab = (e.notification.data && e.notification.data.tab) || "core";
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (cs) {
    for (var i = 0; i < cs.length; i++) { if ("focus" in cs[i]) { cs[i].navigate("/#" + tab).catch(function () { }); return cs[i].focus(); } }
    return self.clients.openWindow("/#" + tab);
  }));
});
