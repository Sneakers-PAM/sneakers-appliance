// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
//
// The box-state poller (docs/edge-fallback.md). A product page loads it
// from /_box/poll.js. It asks /_box/state every second and, while the box
// isn't running or doesn't answer, lays the branded box-state page over
// the product. It never navigates while the box is away, so the tab never
// shows a browser error page; once the box answers running and the page
// itself answers again, it reloads. On the edge fallback's own page it
// updates the words in place and reloads the same way.
(function () {
  "use strict";
  if (window.__sneakersBox) return;
  window.__sneakersBox = true;

  var POLL_MS = 1000;
  var TIMEOUT_MS = 1500;
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
  var reloading = false;
  var ui = null;

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

  function build() {
    var host = el("div", { position: "fixed", inset: "0", zIndex: "2147483647" });
    var shadow = host.attachShadow({ mode: "closed" });
    var bg = el("div", {
      position: "absolute", inset: "0", display: "flex", alignItems: "center", justifyContent: "center",
      textAlign: "center", background: "#14212b", color: "#f4f7fa",
      font: '16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif'
    });
    var box = el("div", { maxWidth: "34rem", padding: "2rem" });
    box.setAttribute("role", "status");
    box.setAttribute("aria-live", "polite");
    var mark = el("p", {
      margin: "0 0 1.5rem", fontWeight: "700", letterSpacing: ".08em", textTransform: "uppercase",
      color: "#8fb3d9", fontSize: ".9rem"
    }, "Sneakers-PAM");
    var spin = el("div", {
      width: "2.25rem", height: "2.25rem", margin: "0 auto 1.5rem", border: "3px solid #2f4252",
      borderTopColor: "#8fb3d9", borderRadius: "50%"
    });
    if (spin.animate && !(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches)) {
      spin.animate([{ transform: "rotate(0deg)" }, { transform: "rotate(360deg)" }], { duration: 1000, iterations: Infinity });
    }
    var title = el("h1", { margin: "0 0 .75rem", fontSize: "1.75rem", fontWeight: "700" });
    var note = el("p", { margin: "0", color: "#c9d4de" });
    box.append(mark, spin, title, note);
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
        marginTop: "1.5rem", padding: ".5rem 1.25rem", font: "inherit", color: "#14212b",
        background: "#8fb3d9", border: "0", borderRadius: ".25rem", cursor: "pointer"
      }, "Reload");
      ui.reload.type = "button";
      ui.reload.addEventListener("click", function () { window.location.reload(); });
      ui.box.append(ui.reload);
    }
  }

  function get(url, method) {
    var ctl = window.AbortController ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, TIMEOUT_MS);
    return fetch(url, { method: method, cache: "no-store", credentials: "same-origin", signal: ctl ? ctl.signal : undefined })
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
        var state = j && typeof j.state === "string" ? j.state : "";
        if (state === "running") {
          if (ui || onPage) return back();
          return;
        }
        if (!WORDS[state]) return;
        last = state;
        show(state, true);
      }, function () {
        misses++;
        if (ui || onPage || misses >= MISSES || WORDS[last]) show(last, false);
      })
      .finally(function () { busy = false; });
  }

  setInterval(tick, POLL_MS);
  tick();
})();
