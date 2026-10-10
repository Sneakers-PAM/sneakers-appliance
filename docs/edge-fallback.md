# The edge fallback and the box-state page

While the box reboots, shuts down, applies an update or is in maintenance, a product URL on the
edge (443) shows a branded box-state page, "Sneakers-PAM is rebooting" and the like, instead of a
browser connection error, and an open product tab goes back to the product by itself once the box
is back. Three pieces do it: the box state, `sneakers-edgefall`, and the poller product pages load.
This is the platform design's edge fallback (Section 3.2), owned by init until platformd (#99)
takes over starting and stopping it around k0s.

## The box state

`StatusService.GetPhase` (public, [osadmin-api.md](osadmin-api.md)) answers `state`:

| State | When |
|---|---|
| `updating` | an update or a product update applies or reverts, through the reboot it ends in; a product apply or revert until the product is ready |
| `rebooting`, `shutting-down` | init has announced a reboot or a shutdown |
| `running` | setup is done, the product's service (k0s) runs and the product is ready |
| `starting` | otherwise: setup isn't done, k0s doesn't run yet, or k0s runs and the product isn't ready yet |
| `maintenance` | an open import holds a phased product after the phases it writes to ([upgrades.md](upgrades.md#the-phases)) |
| `failed` | the product failed to start since k0s last started: a phase failed or wasn't Ready within its timeout, or the product wasn't ready within its ready bound; it holds until k0s starts again (a revert, a re-apply or a reboot) |

**Ready** is the check a product apply waits on ([upgrades.md](upgrades.md)): every workload of
the slot's stacks rolled out, the product's health check and the edge answering. After each k0s
start accessd asks it in the background (every 3 seconds, never on a `GetPhase` itself) until it
passes; during a product apply or revert the apply's own follower decides. For a phased product
the same ask moves it on to its next phase. A product that isn't ready within its ready bound
(`ready.timeout`, else 10 minutes), or a phase that fails or isn't Ready within its own timeout,
leaves the box `failed`: 443 stays on the box-state page, which says "Sneakers-PAM failed to
start" and, under it, the phase and the reason accessd pushed ("Starting sign-in, identity and the
vault: ..."), so a half-started product is never served. The reason comes with accessd's push and
holds while the box stays failed; GetPhase's answer carries none.

Init writes the announcement to `/run/sneakers/box-state` (mode 0644, a tmpfs, so every boot starts
without one) when it accepts a reboot or a shutdown, before the drain and before the screen
([init.md](init.md#the-screen-stays-quiet)). Whoever asked, the :8443 Power page, an update's apply or the
closed shell, it's the same file.

## sneakers-edgefall

An init service in normal operation (`os/rootfs/services.d/edgefall.yaml`), after accessd, as the
`edgefall` user (uid 103) with only `CAP_NET_BIND_SERVICE` as an ambient capability
([init.md](init.md#the-service-table)). Its pre-start, `sneakers-edgefall prepare`, runs as root
and copies the box's :8443 certificate and key (the pair `k0s-interim` hands Traefik as `box-tls`)
from `/var/lib/sneakers/osadmin`, following no links, into `/run/sneakers/edgefall/` (0700, the
files 0600, owned by `edgefall`). Without a whole pair it leaves none, and edgefall never answers
443.

It serves exactly these, and nothing else:

| Request | Answer |
|---|---|
| `GET /_box/state` | `{"state":"rebooting"}`, with `"brand"` when the product has one (below), `Cache-Control: no-store` |
| `GET /_box/events` | the box state as a server-sent-events stream ([below](#the-event-stream)) |
| `GET /_box/poll.js` | the poller |
| `POST /_box/edge-handoff` | loopback only: the edge asking for 80 and 443 (below); `204` |
| `GET /_box/gate` | loopback only: the edge's check for every request on 443 ([the gate](#the-gate)); `204`, or the page |
| `GET /_box/logo` | the product's logo for the poller's overlay, only when its brand has one, from edgefall's own copy (`Content-Security-Policy: default-src 'none'; sandbox`, `nosniff`) |
| anything else, any path, method or host | the branded page, `503`, `Retry-After: 10`, `Sneakers-Box-State: <state>` |

It never serves product content and never proxies. The page has a strict CSP (`default-src
'none'`, the script from itself, its one inline stylesheet by hash, images from itself) and loads the
poller, so a browser that lands on it goes back to the product by itself.

- **Loopback, always:** `127.0.0.1:9180`, plain HTTP. A product edge routes `/_box/` there and uses
  it for its error pages (`502` to `504`), so an open tab gets the state from the same origin. The
  lab edge stack does both (`build/lab/stacks/edge/edge.yaml`, [k0s.md](k0s.md)), and the lab hello
  page loads the poller.
- **80 and 443, while k0s doesn't run and until the edge takes them:** on a box with a product
  bundle installed, edgefall holds `:443` (TLS 1.2 and up, the box's certificate) and `:80` (a
  redirect to https, as Traefik's 80 does) while `GetPhase` says the product doesn't run, and from
  a reboot or a shutdown on. Both or neither: while Traefik still holds 443 it tries again every
  half second. Before a product is installed nothing answers 80 or 443.
- **The handoff:** when k0s starts (edgefall saw it stopped, then running), edgefall keeps both
  until the product's edge asks for them with `POST /_box/edge-handoff` on the loopback listener.
  Traefik's own container asks, from its start command, right before it execs `traefik`
  (`wget ... /_box/edge-handoff || true; exec traefik "$@"`): edgefall lets both go before it
  answers, so 443 is free only for the moment Traefik takes to bind it. An init container asked
  before, and the kubelet then had to start Traefik's container while it started every other pod
  of the product, which left 443 refusing for tens of seconds after a reboot, an update or a
  revert. A failed ask (no edgefall) never stops Traefik. After each handoff edgefall dials 443 on
  loopback until something accepts and logs how long it refused (`edgefall: the edge took 443`,
  `refusedMs`), or an error when nothing took it within `HandoffWait`. An edge that never asks
  gets them `HandoffWait` (2 minutes) after k0s started; Traefik's bind fails until then and the
  kubelet restarts it. A handoff while k0s doesn't run, or after a reboot or a shutdown was seen, is
  ignored. When edgefall starts on a box whose k0s already runs, it holds nothing: Traefik has the
  edge already. The lab edge stack does this (`build/lab/stacks/edge/edge.yaml`); a product's own
  edge needs the same.
- **The state:** edgefall asks accessd's `GetPhase` every half second on `access.sock`, where its
  uid may ask that and nothing else ([access.md](access.md#accesssock)), and serves the last answer,
  so a request never waits on accessd. A reboot or a shutdown holds once seen: accessd stops during
  the drain, and edgefall reads init's announcement itself when accessd doesn't answer. An update's
  reboot stays `updating`. With no answer and no announcement (accessd restarting) the last state
  stays.
- **Through the drain:** a reboot's or a shutdown's drain leaves edgefall running until the power
  goes ([init.md](init.md#the-service-table)), so once k0s has stopped, 443 still answers with the
  page.

## The event stream

`GET /_box/events` streams the box state, so a product page learns at once that an update or a
reboot started, instead of polling `/_box/state`. edgefall serves it on 443 while it holds the
port and on its loopback listener, where the edge routes `/_box/` past the gate. No auth: it carries
the box state only, like `/_box/state`.

- **Headers:** `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering:
  no`. Each write is flushed, and the stream lifts the listener's write timeout for itself.
- **On connect:** `retry: 2000` once, then the current state at once.
- **Each event:** `event: state` and one `data:` line of JSON:
  `{"state":"updating","kind":"product-apply","step":"pods","detail":"Rolling out","since":"2026-10-10T16:00:00Z","seq":7}`.
  `state` is a box state (above); `kind` is `update`, `product-apply`, `reboot`, `shutdown` or
  `null`; `step` and `detail` are an update's active step id and its words (empty otherwise);
  `since` is when this event began (RFC 3339, UTC); `seq` increases with every event. An event is
  sent only when one of `state`, `kind`, `step` or `detail` changes; a slow client skips to the
  newest.
- **Heartbeat:** a `: hb` comment every 15 seconds, so idle proxies keep it open.
- **The push:** accessd tells edgefall the moment it changes, on edgefall's push socket
  (`/run/sneakers/edgefall/push.sock`, in edgefall's own 0700 directory, so only root and edgefall
  reach it), and waits for the answer, which comes once every open stream was sent the event (or
  after half a second). So every open tab hears it before anything stops:
  - an update, a product apply or revert, or a product re-apply (email settings, a host name)
    starting, as `updating` with its kind, pushed as maintenance begins, before the switch, the
    product's stop or the reboot;
  - a reboot or a shutdown from the Power page, before init is asked (a refused one is taken back);
  - each step after that, and the end of the maintenance;
  - `starting`, then `running` once the product is ready, on the way back.
  A push edgefall doesn't take within a second never holds the update up (accessd logs it), and
  edgefall's own poll of `GetPhase` and of init's announcement still runs, so the stream follows
  whatever the push missed, init's own reboots and shutdowns from the closed shell included.
- **A dropped stream:** while edgefall holds 443 itself and lets it go to the edge (the handoff),
  or when the box goes down, the stream ends; the client reconnects (the poller and the product web
  follow the client side of the contract).

## The gate

Every request on 443 passes edgefall's gate before it reaches a route: the edge's `box-gate`
middleware, a Traefik `forwardAuth` to `GET /_box/gate` on the loopback listener, set on the
`websecure` entry point so it covers every router, the product's Ingresses (pages, the API,
sign-in, MCP and OAuth) included. The gate answers `204`, and the request goes on, while the state
is `running`; otherwise it answers the branded page with `503`, `Retry-After` and
`Sneakers-Box-State`, which the edge hands to the client as it is. So from k0s's start until the
product is ready, and through a product apply or revert until the new version is ready, nobody
signs in to a product that isn't ready and no agent writes to it: they get "Sneakers-PAM is
starting" or "Sneakers-PAM is updating".

- **Always through:** edgefall's own paths (`/_box/...`, plain, with no dot segments or escapes),
  so the poller keeps reading the state on the same origin, and requests from the box's own
  loopback (the last `X-Forwarded-For` entry, which Traefik sets itself), so the readiness check
  can ask the product through the edge before the gate opens.
- **Only on loopback:** on 443 edgefall itself answers `/_box/gate` with the page, like any path.

## The product's brand

The page and the overlay carry the installed product's logo and colours when its bundle has a brand
([artifact.md](artifact.md#the-brand)); with no product, or a bundle without one, they keep the base
look. Edgefall reads `/var/lib/sneakers/product/current/brand/` (`--brand-dir`): the current
slot's copy, which only root writes and edgefall only reads. It looks again whenever the slot
`current` names or the files in it change, so applying or reverting a product switches the brand
with it. Each load runs the bundle's brand check again; a brand that fails it is ignored (logged as a
warning) and the base look stays, and colours that fail the contrast check give way to the base
colours while the logo stays.

- **The page:** the logo replaces the wordmark, carried in the page itself as a `data:` image, so
  it shows even when edgefall lets 443 go between the page and another request; the colours are
  added to the page's one stylesheet as the checked `#rrggbb` values. The CSP still pins that
  stylesheet by its hash, so a brand never loosens it: no `unsafe-inline`, no other origin.
- **The state:** `/_box/state` adds `"brand":{"background":"#rrggbb","text":"#rrggbb","accent":"#rrggbb","logo":"/_box/logo"}`
  (each field only when the brand has it).
- **The overlay:** the poller takes the brand from the first state answer that has one, while the
  box still answers, and loads the logo then, so the overlay shows it after the box has gone away.
  It checks the colours itself. A product page's CSP needs `img-src 'self'` for the logo; without
  it the overlay shows the wordmark.

## The poller

A product page includes it:

```html
<script src="/_box/poll.js" defer></script>
```

Where the browser has EventSource (every current one), it opens one stream per page on the relative
`/_box/events` and follows the box's state events (`event: state`, one JSON line with `state`,
`kind`, `step`, `detail`, `since` and `seq`):

- An event switches the page at once: `updating`, `rebooting`, `shutting-down` or `starting` lays
  the box-state page over the product before 443 drops, and `running` after it reloads the page once
  the page itself answers.
- It asks `/_box/state` once when the page loads, for the product's brand, and not again while the
  stream is up.
- A stream that drops while the state isn't `running` is the box restarting: the box-state page
  stays, and the stream is tried again after 1, 2, 4, 8 and then every 10 seconds.
- A stream that drops while the box runs is tried again at once. After 3 failures in a row it asks
  `/_box/state`, and says "Sneakers-PAM can't be reached" only if that fails too.
- While the stream can't open, it asks `/_box/state` every 37.5 to 52.5 seconds (45 with jitter) as
  the fallback.

Without EventSource it polls instead. It asks `/_box/state` once when the page loads (one ask at a
time, each given up after 5 seconds), then:

- about every 45 seconds while the box answers `running`, spread by up to 7.5 seconds either way so
  open tabs don't ask in step;
- every second while the state isn't `running`, while the box doesn't answer, and for 30 seconds
  after one of the page's own `fetch` requests answers with the `Sneakers-Box-State` header or
  fails with a network error (the poller watches the page's `fetch` for that, and asks at once);
- never while the tab is hidden (an ask that fails while it is hidden doesn't count as a miss); when
  the tab is shown again it asks at once.

While the state isn't `running`, it lays the branded page over the product (a closed shadow root, styled through the DOM,
so a product's CSP needs only `script-src 'self'` and `connect-src 'self'`). When nothing answers,
it keeps the last state it saw; two missed answers in a row with nothing seen yet say "Sneakers-PAM
can't be reached", and after a shutdown "Sneakers-PAM has shut down". It never navigates while the
box is away, so the tab never shows a browser error page.

Once the state is `running` again, it asks the page itself (`HEAD`), and reloads only when that
answers `2xx` without the `Sneakers-Box-State` header, so it never reloads into the fallback page or
an edge error. The reload opens a new TLS session; after 10 minutes the page offers a Reload
button, which is how the browser gets to check a certificate that changed, as the :8443 restart
page does.

| Window | What answers 443 | What an open tab shows |
|---|---|---|
| running | Traefik, the product | the product; the poller asks Traefik's `/_box/state` |
| reboot or shutdown accepted, k0s still stopping | Traefik, `/_box/state` from edgefall | the overlay at the next ask (within about 50 seconds), or at once when a page request meets the fallback |
| k0s stopped, the box still draining | edgefall | the overlay; a new visit gets the page |
| the power is off, firmware, early boot | nothing | the overlay, kept |
| booted, k0s not started | edgefall (`starting`) | the overlay |
| k0s starting, Traefik not bound yet | edgefall (`starting`), until the edge's handoff | the overlay |
| the handoff, Traefik binding | nothing (about a second) | the overlay, kept |
| Traefik up, the product's services still starting | Traefik, every request gated: the page (`starting`) | the overlay |
| a product apply or revert, until the new version is ready | Traefik, every request gated: the page (`updating`) | the overlay |
| the product ready | Traefik, the product | the page reloads into the product |
