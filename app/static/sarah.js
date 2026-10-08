/* S.A.R.A.H. - the core: a rotating network sphere with an energy core and data streams flowing in.
   SarahCore(canvas, {state, mini})   states: off | calm | think | alert | act
   api: setState(name), pulse(), pause(bool), stop()
   The colour and speed show what S.A.R.A.H. is doing; nothing here talks to the firewall. */
(function (global) {
  "use strict";
  var TAU = Math.PI * 2;
  var STATES = {
    off:   { h: 215, s: 8,   l: 52, glow: 0.10, rot: 0.05, feed: 0,   wave: 0,   hud: 0.16, size: 0.92, amp: 0.05 },
    calm:  { h: 188, s: 100, l: 58, glow: 0.55, rot: 0.16, feed: 0.9, wave: 0.5, hud: 0.9,  size: 1.0,  amp: 0.25 },
    think: { h: 268, s: 100, l: 68, glow: 0.85, rot: 0.55, feed: 4.5, wave: 1.3, hud: 1,    size: 1.1,  amp: 0.8 },
    alert: { h: 356, s: 100, l: 58, glow: 0.95, rot: 0.38, feed: 2.6, wave: 1.7, hud: 1,    size: 1.07, amp: 0.95 },
    act:   { h: 322, s: 100, l: 64, glow: 1.0,  rot: 0.75, feed: 3.4, wave: 2.3, hud: 1,    size: 1.14, amp: 0.9 }
  };
  var KEYS = ["h", "s", "l", "glow", "rot", "feed", "wave", "hud", "size", "amp"];
  function hueLerp(a, b, k) { var d = ((b - a + 540) % 360) - 180; return (a + d * k + 360) % 360; }
  function approach(cur, tgt, k) {
    KEYS.forEach(function (n) { cur[n] = n === "h" ? hueLerp(cur.h, tgt.h, k) : cur[n] + (tgt[n] - cur[n]) * k; });
  }
  function base(canvas, opts, draw) {
    opts = opts || {};
    var ctx = canvas.getContext("2d"), cur = Object.assign({}, STATES[opts.state || "off"]), tgt = Object.assign({}, cur), name = opts.state || "off";
    var W = 0, H = 0, running = true, paused = false, last = 0, acc = 0, t = 0, raf = null, fps = opts.fps || (opts.mini ? 20 : 60), step = 1000 / fps - 2;
    var api = { pulses: [] };
    function fit() {
      var d = Math.min(2, global.devicePixelRatio || 1);
      W = canvas.clientWidth || canvas.width; H = canvas.clientHeight || canvas.height;
      canvas.width = Math.round(W * d); canvas.height = Math.round(H * d); ctx.setTransform(d, 0, 0, d, 0, 0);
    }
    fit();
    api.fit = fit;                                              /* companion: lets the app re-measure after a rotation or a window resize */
    api.setState = function (n) { if (!STATES[n] || n === name) return; name = n; tgt = Object.assign({}, STATES[n]); if (n !== "off" && n !== "calm") api.pulse(); };
    api.pulse = function () { api.pulses.push(t); if (api.pulses.length > 4) api.pulses.shift(); };
    api.pause = function (v) { paused = !!v; };
    api.stop = function () { running = false; if (raf) cancelAnimationFrame(raf); };
    api.state = function () { return name; };
    function frame(now) {
      if (!running) return;
      raf = requestAnimationFrame(frame);
      if (paused || (global.document && document.hidden)) { last = now; return; }
      if (now - last < ((opts.mini && name === "off") ? 98 : step)) return;
      var dt = Math.min(0.05, (now - last) / 1000 || 0.016); last = now; t += dt;
      approach(cur, tgt, Math.min(1, dt * 3.2));
      ctx.clearRect(0, 0, W, H);
      draw(ctx, W, H, t, dt, cur, name, api, opts);
    }
    raf = requestAnimationFrame(frame);
    return api;
  }
  function col(c, a, dl) { return "hsla(" + c.h.toFixed(0) + "," + c.s.toFixed(0) + "%," + Math.min(96, c.l + (dl || 0)).toFixed(0) + "%," + Math.max(0, a).toFixed(3) + ")"; }
  function colH(c, dh, a, dl) { return "hsla(" + ((c.h + dh + 360) % 360).toFixed(0) + "," + c.s.toFixed(0) + "%," + Math.min(96, c.l + (dl || 0)).toFixed(0) + "%," + Math.max(0, a).toFixed(3) + ")"; }

  /* ================================================================ CORE */
  function SarahCore(canvas, opts) {
    opts = opts || {};
    var mini = !!opts.mini, BATCH = mini || !!opts.batch, N = opts.nodes || (mini ? 64 : 230), TICKS = opts.ticks || 120, pts = [], edges = [], energy = [], streams = [];
    var ga = Math.PI * (3 - Math.sqrt(5)), i, j;
    for (i = 0; i < N; i++) { var y = 1 - (i / (N - 1)) * 2, r = Math.sqrt(1 - y * y), th = ga * i; pts.push([Math.cos(th) * r, y, Math.sin(th) * r]); energy.push(0); }
    var thr = mini ? 0.66 : 0.4, deg = [];
    for (i = 0; i < N; i++) deg.push(0);
    for (i = 0; i < N; i++) for (j = i + 1; j < N; j++) {
      var dx = pts[i][0] - pts[j][0], dy = pts[i][1] - pts[j][1], dz = pts[i][2] - pts[j][2];
      if (dx * dx + dy * dy + dz * dz < thr * thr && deg[i] < 6 && deg[j] < 6) { edges.push([i, j]); deg[i]++; deg[j]++; }
    }
    var feedAcc = 0, proj = [];
    return base(canvas, opts, function (ctx, W, H, t, dt, c, name, api) {
      var cx = W / 2, cy = H / 2, R = Math.min(W, H) * (mini ? 0.3 : 0.215) * c.size, shake = name === "alert" ? 1.4 : 0;
      if (shake) { cx += (Math.random() - 0.5) * shake; cy += (Math.random() - 0.5) * shake; }
      var ay = t * c.rot, ax = 0.42 + Math.sin(t * 0.23) * 0.12, cyr = Math.cos(ay), syr = Math.sin(ay), cxr = Math.cos(ax), sxr = Math.sin(ax);
      ctx.globalCompositeOperation = "lighter";
      /* outer glow */
      var g = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 2.3);
      g.addColorStop(0, col(c, c.glow * 0.30)); g.addColorStop(0.45, col(c, c.glow * 0.10)); g.addColorStop(1, col(c, 0));
      ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
      /* HUD ring */
      if (!mini) {
        ctx.save(); ctx.translate(cx, cy); ctx.rotate(t * 0.05 * (c.rot > 0.1 ? 1 : 0.3));
        var tr = R * 2.02;
        /* all ticks of one width in ONE path: two strokes per frame instead of one per tick */
        ctx.strokeStyle = col(c, 0.55 * c.hud);
        [true, false].forEach(function (major) {
          ctx.lineWidth = major ? 1.4 : 0.8; ctx.beginPath();
          for (i = 0; i < TICKS; i++) {
            if ((i % 10 === 0) !== major) continue;
            var a = (i / TICKS) * TAU, l = i % 10 === 0 ? 9 : i % 5 === 0 ? 5 : 2.5;
            ctx.moveTo(Math.cos(a) * tr, Math.sin(a) * tr); ctx.lineTo(Math.cos(a) * (tr + l), Math.sin(a) * (tr + l));
          }
          ctx.stroke();
        });
        ctx.restore();
        ctx.save(); ctx.translate(cx, cy);
        [[1.88, 0.35, 120, 0.7], [1.78, -0.6, 70, 0.5]].forEach(function (rr, k) {
          ctx.rotate(t * rr[1] * (0.4 + c.rot)); ctx.strokeStyle = colH(c, k * 40, rr[3] * c.hud); ctx.lineWidth = 2.2 - k * 0.8; ctx.setLineDash([rr[2], 30, 12, 30]); ctx.beginPath(); ctx.arc(0, 0, R * rr[0], 0, TAU); ctx.stroke();
        });
        ctx.setLineDash([]); ctx.restore();
      }
      /* orbit rings with comets */
      [[1.5, 0.35, 0.5, 0.6, 0], [1.34, 0.28, -0.9, -0.8, 60], [1.62, 0.22, 1.5, 0.45, -50]].slice(0, mini ? 1 : 3).forEach(function (o) {
        ctx.save(); ctx.translate(cx, cy); ctx.rotate(o[2]); ctx.scale(1, o[1]);
        ctx.strokeStyle = colH(c, o[4], 0.22 * c.hud); ctx.lineWidth = 1 / o[1] * 0.9; ctx.beginPath(); ctx.arc(0, 0, R * o[0], 0, TAU); ctx.stroke();
        var a0 = t * o[3] * (0.5 + c.rot * 2);
        for (var k = 0, KN = mini ? 7 : 16; k < KN; k++) { var aa = a0 - k * (mini ? 0.16 : 0.07); ctx.fillStyle = colH(c, o[4], (1 - k / KN) * 0.9 * c.hud, 14); ctx.beginPath(); ctx.arc(Math.cos(aa) * R * o[0], Math.sin(aa) * R * o[0], (2.6 - k * 0.14) / o[1] * 0.55, 0, TAU); ctx.fill(); }
        ctx.restore();
      });
      /* project the sphere */
      for (i = 0; i < N; i++) {
        var p = pts[i], x1 = p[0] * cyr + p[2] * syr, z1 = -p[0] * syr + p[2] * cyr, y2 = p[1] * cxr - z1 * sxr, z2 = p[1] * sxr + z1 * cxr;
        var persp = 1 / (1 - z2 * 0.3);
        proj[i] = [cx + x1 * R * persp, cy + y2 * R * persp, z2, p[1]];
        energy[i] *= 0.955;
      }
      var wv = c.wave;
      /* edges */
      ctx.lineWidth = mini ? 0.9 : 1;
      var EB = BATCH ? [[], [], [], []] : null, EA = [0.05, 0.12, 0.22, 0.42];
      for (i = 0; i < edges.length; i++) {
        var A = proj[edges[i][0]], B = proj[edges[i][1]], zz = (A[2] + B[2]) * 0.5, my = (A[3] + B[3]) * 0.5;
        var w = wv ? Math.pow(Math.max(0, Math.sin(t * wv * 2.2 - my * 3.1)), 8) : 0, e = Math.max(energy[edges[i][0]], energy[edges[i][1]]);
        var al = (0.05 + 0.2 * (zz + 1) / 2) * (0.55 + c.glow * 0.7) + w * 0.5 * c.glow + e * 0.55;
        if (BATCH) { EB[al < 0.08 ? 0 : al < 0.16 ? 1 : al < 0.3 ? 2 : 3].push(A, B); continue; }
        ctx.strokeStyle = colH(c, my * 34, al); ctx.beginPath(); ctx.moveTo(A[0], A[1]); ctx.lineTo(B[0], B[1]); ctx.stroke();
      }
      if (BATCH) EB.forEach(function (seg, bi) { if (!seg.length) return; ctx.strokeStyle = colH(c, 40, EA[bi] * (0.6 + c.glow * 0.7)); ctx.beginPath(); for (var q = 0; q < seg.length; q += 2) { ctx.moveTo(seg[q][0], seg[q][1]); ctx.lineTo(seg[q + 1][0], seg[q + 1][1]); } ctx.stroke(); });
      /* nodes */
      var NB = BATCH ? [[], [], []] : null, NA = [0.3, 0.6, 0.95];
      for (i = 0; i < N; i++) {
        var P = proj[i], depth = (P[2] + 1) / 2, ww = wv ? Math.pow(Math.max(0, Math.sin(t * wv * 2.2 - P[3] * 3.1)), 6) : 0;
        var rr = (mini ? 1.3 : 1.7) * (0.6 + 0.6 * depth) * (1 + energy[i] * 1.8 + ww * 0.8), aa2 = (0.25 + 0.6 * depth) * (0.45 + c.glow * 0.6) + energy[i] * 0.5 + ww * 0.3;
        if (BATCH) { NB[aa2 < 0.35 ? 0 : aa2 < 0.65 ? 1 : 2].push(P[0], P[1], rr); continue; }
        ctx.fillStyle = colH(c, P[3] * 34, aa2, 6 + energy[i] * 20); ctx.beginPath(); ctx.arc(P[0], P[1], rr, 0, TAU); ctx.fill();
      }
      if (BATCH) NB.forEach(function (pt, bi) { if (!pt.length) return; ctx.fillStyle = colH(c, 20, NA[bi] * (0.55 + c.glow * 0.5), 12); ctx.beginPath(); for (var q = 0; q < pt.length; q += 3) { ctx.moveTo(pt[q] + pt[q + 2], pt[q + 1]); ctx.arc(pt[q], pt[q + 1], pt[q + 2], 0, TAU); } ctx.fill(); });
      /* pulses (shock rings from the core) */
      for (i = api.pulses.length - 1; i >= 0; i--) {
        var age = t - api.pulses[i];
        if (age > 1.8) { api.pulses.splice(i, 1); continue; }
        var pr = R * (0.2 + age * 1.35), pa = (1 - age / 1.8) * 0.8 * c.glow;
        ctx.strokeStyle = col(c, pa, 12); ctx.lineWidth = 2.4 * (1 - age / 1.8) + 0.5; ctx.beginPath(); ctx.arc(cx, cy, pr, 0, TAU); ctx.stroke();
        for (j = 0; j < N; j += 1) if (proj[j][2] > -0.2 && Math.abs(Math.hypot(proj[j][0] - cx, proj[j][1] - cy) - pr) < R * 0.12) energy[j] = Math.min(1, energy[j] + 0.25);
      }
      /* data streams flowing in */
      feedAcc += dt * c.feed * (mini ? 0.5 : 1);
      while (feedAcc >= 1) { feedAcc -= 1; if (mini && streams.length >= 5) continue; streams.push({ a: Math.random() * TAU, r: R * (2.2 + Math.random() * 0.4), v: 0.8 + Math.random() * 0.9, sp: (Math.random() - 0.5) * 1.1, m: Math.random() < 0.22 }); }
      for (i = streams.length - 1; i >= 0; i--) {
        var s = streams[i], pr0 = s.r, pa0 = s.a;
        s.r -= s.v * R * dt * 1.1; s.a += s.sp * dt;
        if (s.r < R * 1.03) { energy[(Math.random() * N) | 0] = 1; streams.splice(i, 1); continue; }
        var x0 = cx + Math.cos(pa0) * pr0, y0 = cy + Math.sin(pa0) * pr0 * 0.92, x1b = cx + Math.cos(s.a) * s.r, y1b = cy + Math.sin(s.a) * s.r * 0.92;
        var gr; if (BATCH) gr = colH(c, s.m ? 50 : 0, 0.7, 14); else { gr = ctx.createLinearGradient(x0, y0, x1b, y1b); gr.addColorStop(0, colH(c, s.m ? 50 : 0, 0)); gr.addColorStop(1, colH(c, s.m ? 50 : 0, 0.85, 14)); }
        ctx.strokeStyle = gr; ctx.lineWidth = 1.4; ctx.beginPath(); ctx.moveTo(x0 - (x1b - x0) * 5, y0 - (y1b - y0) * 5); ctx.lineTo(x1b, y1b); ctx.stroke();
      }
      /* energy core */
      var br = 1 + 0.07 * Math.sin(t * (1.6 + wv)) + (name === "alert" ? Math.random() * 0.08 : 0);
      var cg = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 0.62 * br);
      cg.addColorStop(0, "rgba(255,255,255," + (0.5 + c.glow * 0.5).toFixed(2) + ")"); cg.addColorStop(0.18, col(c, 0.75 * c.glow + 0.1, 16)); cg.addColorStop(0.6, col(c, 0.22 * c.glow)); cg.addColorStop(1, col(c, 0));
      ctx.fillStyle = cg; ctx.beginPath(); ctx.arc(cx, cy, R * 0.62 * br, 0, TAU); ctx.fill();
      ctx.globalCompositeOperation = "source-over";
    });
  }

  global.SarahCore = SarahCore;
})(window);
