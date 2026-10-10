// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
//
// The box-state poller (docs/edge-fallback.md). A product page loads it
// from /_box/poll.js. It asks /_box/state about every 45 seconds while the
// box runs, and every second while it doesn't, can't be reached, or one of
// the page's own requests just failed; a hidden tab doesn't ask. While the
// box isn't running or doesn't answer, it lays the branded box-state page over
// the product, in the installed product's colours and logo when its
// bundle carries a brand (the state answer names them). It never navigates while the box is away, so the tab never
// shows a browser error page; once the box answers running and the page
// itself answers again, it reloads. On the edge fallback's own page it
// updates the words in place and reloads the same way.
(function () {
  "use strict";
  if (window.__sneakersBox) return;
  window.__sneakersBox = true;

  // Every second while something is under way; about every 45 seconds,
  // spread by up to 7.5 seconds either way so open tabs don't ask in step,
  // while the box runs.
  var FAST_MS = 1000;
  var STEADY_MS = 45000;
  var JITTER_MS = 7500;
  // How long the poller keeps asking every second after a page request
  // answered with the box-state header or failed.
  var ALERT_MS = 30000;
  // Long enough for a box under load or a browser queueing the ask behind
  // the page's own requests: a shorter one gave up on answers that were on
  // their way, and each miss made it ask faster. Only one ask is out at a
  // time.
  var TIMEOUT_MS = 5000;
  // A single lost answer isn't the box going away.
  var MISSES = 2;
  // After this long the page offers a reload, which is how the browser
  // checks a certificate that changed.
  var SLOW_MS = 10 * 60 * 1000;
  var STATE_HEADER = "Sneakers-Box-State";

  var WORDS = {
    starting: ["Sneakers-PAM is starting", "This page reloads by itself when it's ready."],
    rebooting: ["Sneakers-PAM is rebooting", "It comes back by itself. This page reloads when it's ready."],
    "shutting-down": ["Sneakers-PAM is shutting down", "It powers off by itself. Power it on again to use it."],
    updating: ["Sneakers-PAM is updating", "It comes back by itself when the update is done. This page reloads when it's ready."],
    maintenance: ["Sneakers-PAM is in maintenance", "It comes back when the maintenance is over. This page reloads when it's ready."]
  };
  var OFF = ["Sneakers-PAM has shut down", "Power it on again to use it. This page reloads when it's back."];
  var UNREACHABLE = ["Sneakers-PAM can't be reached", "This page reloads when it's back."];

  var root = document.documentElement;
  var onPage = root.hasAttribute("data-sneakers-box");
  var last = onPage ? root.getAttribute("data-sneakers-box") : "running";
  var misses = 0;
  var shownAt = onPage ? Date.now() : 0;
  var busy = false;
  var seen = last;
  var alertAt = -ALERT_MS;
  var timer = null;
  var realFetch = window.fetch.bind(window);
  var reloading = false;
  var ui = null;
  // The base look; the state answer's brand replaces it.
  var look = { background: "#14212b", text: "#f4f7fa", accent: "#8fb3d9", muted: "#c9d4de", track: "#2f4252" };
  var HEX = /^#[0-9a-f]{6}$/;
  var logo = null;
  var branded = false;

  function words(state, reachable) {
    if (!reachable) {
      if (last === "shutting-down") return OFF;
      if (WORDS[last]) return WORDS[last];
      return UNREACHABLE;
    }
    return WORDS[state] || WORDS.starting;
  }

  function el(tag, style, text) {
    var e = document.createElement(tag);
    Object.assign(e.style, style);
    if (text) e.textContent = text;
    return e;
  }

  function mix(a, b, w) {
    var out = "#";
    for (var i = 1; i < 7; i += 2) {
      var v = Math.round(parseInt(a.substr(i, 2), 16) * w + parseInt(b.substr(i, 2), 16) * (1 - w));
      out += (v < 16 ? "0" : "") + v.toString(16);
    }
    return out;
  }

  // The brand is taken once, while the box answers, so the logo is loaded
  // before the box goes away and the overlay never asks for it later.
  function brand(b) {
    if (branded || onPage || !b || typeof b !== "object") return;
    branded = true;
    if (HEX.test(b.background) && HEX.test(b.text) && HEX.test(b.accent)) {
      look = { background: b.background, text: b.text, accent: b.accent, muted: b.text, track: mix(b.accent, b.background, 0.3) };
    }
    if (b.logo === "/_box/logo") {
      logo = el("img", { display: "block", maxWidth: "12rem", maxHeight: "4rem", margin: "0 auto 1.5rem" });
      logo.alt = "Sneakers-PAM";
      logo.addEventListener("error", function () { logo = null; });
      logo.src = "/_box/logo";
    }
  }

  function build() {
    var host = el("div", { position: "fixed", inset: "0", zIndex: "2147483647" });
    var shadow = host.attachShadow({ mode: "closed" });
    var bg = el("div", {
      position: "absolute", inset: "0", display: "flex", alignItems: "center", justifyContent: "center",
      textAlign: "center", background: look.background, color: look.text,
      font: '16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif'
    });
    var box = el("div", { maxWidth: "34rem", padding: "2rem" });
    box.setAttribute("role", "status");
    box.setAttribute("aria-live", "polite");
    var mark = el("p", {
      margin: "0 0 1.5rem", fontWeight: "700", letterSpacing: ".08em", textTransform: "uppercase",
      color: look.accent, fontSize: ".9rem"
    }, "Sneakers-PAM");
    var spin = el("div", {
      width: "2.25rem", height: "2.25rem", margin: "0 auto 1.5rem", border: "3px solid " + look.track,
      borderTopColor: look.accent, borderRadius: "50%"
    });
    if (spin.animate && !(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches)) {
      spin.animate([{ transform: "rotate(0deg)" }, { transform: "rotate(360deg)" }], { duration: 1000, iterations: Infinity });
    }
    var title = el("h1", { margin: "0 0 .75rem", fontSize: "1.75rem", fontWeight: "700" });
    var note = el("p", { margin: "0", color: look.muted });
    box.append(logo && logo.complete && logo.naturalWidth ? logo : mark, spin, title, note);
    bg.append(box);
    shadow.append(bg);
    root.append(host);
    return { host: host, box: box, title: title, note: note, reload: null };
  }

  function pageUI() {
    return {
      box: document.querySelector("main") || document.body,
      title: document.getElementById("sneakers-box-title"),
      note: document.getElementById("sneakers-box-note"),
      reload: null
    };
  }

  function show(state, reachable) {
    if (!ui) {
      ui = onPage ? pageUI() : build();
      if (!shownAt) shownAt = Date.now();
    }
    var w = words(state, reachable);
    if (ui.title && ui.title.textContent !== w[0]) ui.title.textContent = w[0];
    if (ui.note && ui.note.textContent !== w[1]) ui.note.textContent = w[1];
    if (!ui.reload && Date.now() - shownAt > SLOW_MS) {
      ui.reload = el("button", {
        marginTop: "1.5rem", padding: ".5rem 1.25rem", font: "inherit", color: look.background,
        background: look.accent, border: "0", borderRadius: ".25rem", cursor: "pointer"
      }, "Reload");
      ui.reload.type = "button";
      ui.reload.addEventListener("click", function () { window.location.reload(); });
      ui.box.append(ui.reload);
    }
  }

  function get(url, method) {
    var ctl = window.AbortController ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, TIMEOUT_MS);
    return realFetch(url, { method: method, cache: "no-store", credentials: "same-origin", signal: ctl ? ctl.signal : undefined })
      .finally(function () { clearTimeout(timer); });
  }

  // The box is running again: reload once the page itself answers, and
  // not with the edge fallback's page.
  function back() {
    return get(window.location.href, "HEAD").then(function (res) {
      if (res.ok && !res.headers.get(STATE_HEADER) && !reloading) {
        reloading = true;
        window.location.reload();
      }
    }, function () {});
  }

  function steady() {
    return seen === "running" && !ui && !onPage && misses === 0 && Date.now() - alertAt >= ALERT_MS;
  }

  function delay() {
    return steady() ? Math.round(STEADY_MS - JITTER_MS + Math.random() * 2 * JITTER_MS) : FAST_MS;
  }

  function schedule(ms) {
    if (timer !== null) clearTimeout(timer);
    timer = null;
    if (document.hidden || reloading) return;
    timer = setTimeout(function () { timer = null; tick(); }, ms);
  }

  // One of the page's own requests met the box's fallback or no answer at
  // all: ask now, and every second for a while.
  function alert() {
    alertAt = Date.now();
    if (!busy) schedule(0);
  }

  window.fetch = function () {
    return realFetch.apply(window, arguments).then(function (res) {
      if (res && res.headers && res.headers.get(STATE_HEADER)) alert();
      return res;
    }, function (err) {
      if (!err || err.name !== "AbortError") alert();
      throw err;
    });
  };

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) schedule(0);
    else if (!busy) tick();
  });

  function tick() {
    if (busy || reloading) return;
    busy = true;
    get("/_box/state", "GET")
      .then(function (res) {
        if (!res.ok) throw new Error("state " + res.status);
        return res.json();
      })
      .then(function (j) {
        misses = 0;
        if (j) brand(j.brand);
        var state = j && typeof j.state === "string" ? j.state : "";
        seen = state;
        if (state === "running") {
          if (ui || onPage) return back();
          return;
        }
        if (!WORDS[state]) return;
        last = state;
        show(state, true);
      }, function () {
        // A browser holds back a hidden tab's requests and timers, so an
        // ask that fails while hidden says nothing about the box.
        if (document.hidden) return;
        misses++;
        if (ui || onPage || misses >= MISSES || WORDS[last]) show(last, false);
      })
      .finally(function () {
        busy = false;
        schedule(delay());
      });
  }

  tick();
})();
