// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
//
// Runs poll.js on a fake clock and a fake page, and prints when it asked
// /_box/state in each scenario, as JSON. Usage: node pollclock.js poll.js
"use strict";

const fs = require("fs");
const vm = require("vm");

const source = fs.readFileSync(process.argv[2], "utf8");

function element() {
  const e = {
    style: {},
    children: [],
    attrs: {},
    textContent: "",
    setAttribute(k, v) { e.attrs[k] = v; },
    hasAttribute(k) { return k in e.attrs; },
    getAttribute(k) { return k in e.attrs ? e.attrs[k] : null; },
    append(...c) { e.children.push(...c); },
    addEventListener() {},
    attachShadow() { return element(); },
  };
  return e;
}

// One tab: poll.js with its own clock, timers, page and box.
function tab(seed) {
  let now = 0;
  let timers = [];
  let nextId = 1;
  let rand = seed;
  const asks = [];
  const listeners = {};
  const box = { state: "running", reachable: true, latency: 0, inFlight: 0, maxInFlight: 0, aborted: 0 };
  const document = {
    hidden: false,
    documentElement: element(),
    body: element(),
    createElement: () => element(),
    querySelector: () => null,
    getElementById: () => null,
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
  };
  const headers = (h) => ({ get: (k) => (h[k] === undefined ? null : h[k]) });
  const window = {
    location: { href: "https://box.example.org/", reload() { window.reloads++; } },
    reloads: 0,
    AbortController,
    // The page's own requests and the poller's asks both come here.
    fetch(url, opts) {
      if (url === "/_box/state") {
        asks.push(now);
        if (!box.reachable) return Promise.reject(new TypeError("network"));
        const answer = { ok: true, headers: headers({}), json: () => Promise.resolve({ state: box.state }) };
        if (!box.latency) return Promise.resolve(answer);
        // A slow answer: it comes after box.latency on the fake clock,
        // unless the poller gives up on it first.
        box.inFlight++;
        box.maxInFlight = Math.max(box.maxInFlight, box.inFlight);
        return new Promise((resolve, reject) => {
          const id = ctx.setTimeout(() => { box.inFlight--; resolve(answer); }, box.latency);
          if (opts && opts.signal) {
            opts.signal.addEventListener("abort", () => {
              ctx.clearTimeout(id);
              box.inFlight--;
              box.aborted++;
              reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
            });
          }
        });
      }
      const next = window.__next;
      window.__next = null;
      return next || Promise.resolve({ ok: true, headers: headers({}) });
    },
  };
  const ctx = {
    window,
    document,
    AbortController,
    fetch: (...a) => window.fetch(...a),
    setTimeout(fn, ms) { const id = nextId++; timers.push({ id, at: now + Math.max(0, ms || 0), fn }); return id; },
    clearTimeout(id) { timers = timers.filter((t) => t.id !== id); },
    setInterval(fn, ms) {
      const id = nextId++;
      const every = () => { timers.push({ id, at: now + ms, fn: () => { every(); fn(); } }); };
      every();
      return id;
    },
    clearInterval(id) { timers = timers.filter((t) => t.id !== id); },
    Date: { now: () => now },
    Math: Object.assign(Object.create(Math), {
      random() { rand = (rand * 1103515245 + 12345) % 2147483648; return rand / 2147483648; },
    }),
    Promise,
    Error,
    TypeError,
    Object,
  };
  vm.createContext(ctx);
  const flush = () => new Promise((r) => setImmediate(r));
  const t = {
    box,
    asks,
    document,
    window,
    now: () => now,
    async start() { vm.runInContext(source, ctx); for (let i = 0; i < 5; i++) await flush(); },
    async until(end) {
      for (;;) {
        timers.sort((a, b) => a.at - b.at || a.id - b.id);
        const next = timers[0];
        if (!next || next.at > end) break;
        timers.shift();
        now = next.at;
        next.fn();
        for (let i = 0; i < 5; i++) await flush();
      }
      now = end;
    },
    async visibility(hidden) {
      document.hidden = hidden;
      for (const fn of listeners.visibilitychange || []) fn();
      for (let i = 0; i < 5; i++) await flush();
    },
  };
  return t;
}

const gaps = (xs) => xs.slice(1).map((x, i) => x - xs[i]);
const MIN = 60 * 1000;

async function main() {
  const out = {};

  // Running: one ask at load, then about every 45 s.
  {
    const a = tab(1);
    const b = tab(2);
    await a.start();
    await b.start();
    await a.until(10 * MIN);
    await b.until(10 * MIN);
    out.running = { first: a.asks[0], gaps: gaps(a.asks), other: gaps(b.asks) };
  }

  // Not running: every second.
  {
    const a = tab(3);
    a.box.state = "rebooting";
    await a.start();
    await a.until(30 * 1000);
    out.rebooting = { gaps: gaps(a.asks) };
  }

  // Unreachable: every second.
  {
    const a = tab(4);
    await a.start();
    await a.until(MIN);
    a.box.reachable = false;
    const from = a.asks.length;
    await a.until(3 * MIN);
    out.unreachable = { gaps: gaps(a.asks.slice(from)) };
  }

  // A page request answered with Sneakers-Box-State, then one that fails:
  // each makes the poller ask at once.
  {
    const a = tab(5);
    await a.start();
    await a.until(MIN + 5000);
    const at = a.now();
    await callPage(a, { headers: { "Sneakers-Box-State": "rebooting" } });
    const afterHeader = a.asks.filter((x) => x >= at);
    await a.until(at + 20 * 1000);
    const fastWhile = gaps(a.asks.filter((x) => x >= at));
    await a.until(at + 5 * MIN);
    const later = gaps(a.asks.filter((x) => x >= at + 2 * MIN));
    const at2 = a.now();
    await callPage(a, { fail: true });
    const afterError = a.asks.filter((x) => x >= at2);
    out.kick = { header: afterHeader.map((x) => x - at), fastWhile, later, error: afterError.map((x) => x - at2) };
  }

  // Hidden: no asks; shown again: one at once.
  {
    const a = tab(6);
    await a.start();
    await a.until(MIN);
    await a.visibility(true);
    const hiddenAt = a.now();
    await a.until(hiddenAt + 10 * MIN);
    const whileHidden = a.asks.filter((x) => x > hiddenAt).length;
    const shownAt = a.now();
    await a.visibility(false);
    const onShow = a.asks.filter((x) => x >= shownAt).map((x) => x - shownAt);
    out.hidden = { whileHidden, onShow };
  }

  // A slow box (2.5 s an answer): no ask is given up on, and asks never
  // overlap, while it runs or while it reboots.
  {
    const a = tab(7);
    a.box.latency = 2500;
    await a.start();
    await a.until(5 * MIN);
    a.box.state = "rebooting";
    await a.until(6 * MIN);
    out.slow = { aborted: a.box.aborted, maxInFlight: a.box.maxInFlight, asks: a.asks.length };
  }

  // An ask in flight when the tab is hidden that fails isn't the box going
  // away: shown again, there's no overlay.
  {
    const a = tab(8);
    await a.start();
    await a.until(MIN);
    a.box.reachable = false;
    await a.visibility(true);
    await a.until(2 * MIN);
    a.box.reachable = true;
    await a.visibility(false);
    await a.until(2 * MIN + 5000);
    out.thaw = { overlay: a.document.documentElement.children.length };
  }

  process.stdout.write(JSON.stringify(out));
}

// callPage makes one request of the page's own through the fetch poll.js
// may have wrapped, answered as res says.
async function callPage(t, res) {
  // The fake fetch underneath answers the page's request.
  const answer = res.fail
    ? Promise.reject(new TypeError("network"))
    : Promise.resolve({ ok: false, status: 503, headers: { get: (k) => (res.headers[k] === undefined ? null : res.headers[k]) } });
  answer.catch(() => {});
  t.window.__next = answer;
  try { await t.window.fetch("/api/graphql"); } catch (e) { void e; }
  await t.until(t.now());
}

main().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
