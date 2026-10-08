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
| `updating` | an update or a product update applies or reverts, through the reboot it ends in |
| `rebooting`, `shutting-down` | init has announced a reboot or a shutdown |
| `running` | setup is done and the product's service (k0s) runs |
| `starting` | otherwise: setup isn't done, or k0s doesn't run yet |
| `maintenance` | reserved for platformd's maintenance mode; nothing answers it yet |

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

It serves exactly three things, and nothing else:

| Request | Answer |
|---|---|
| `GET /_box/state` | `{"state":"rebooting"}`, `Cache-Control: no-store` |
| `GET /_box/poll.js` | the poller |
| anything else, any path, method or host | the branded page, `503`, `Retry-After: 10`, `Sneakers-Box-State: <state>` |

It never serves product content and never proxies. The page has a strict CSP (`default-src
'none'`, the script from itself, its one inline stylesheet by hash) and loads the poller, so a
browser that lands on it goes back to the product by itself.

- **Loopback, always:** `127.0.0.1:9180`, plain HTTP. A product edge routes `/_box/` there and uses
  it for its error pages (`502` to `504`), so an open tab gets the state from the same origin.
- **80 and 443, while k0s doesn't run:** on a box with a product bundle installed, edgefall holds
  `:443` (TLS 1.2 and up, the box's certificate) and `:80` (a redirect to https, as Traefik's 80
  does) while `GetPhase` says the product doesn't run, and from a reboot or a shutdown on. Both or
  neither: while Traefik still holds 443 it tries again every half second, and it lets both go as
  soon as k0s runs again, long before Traefik binds them, so the two never hold them together.
  Before a product is installed nothing answers 80 or 443.
- **The state:** edgefall asks accessd's `GetPhase` every half second on `access.sock`, where its
  uid may ask that and nothing else ([access.md](access.md#accesssock)), and serves the last answer,
  so a request never waits on accessd. A reboot or a shutdown holds once seen: accessd stops during
  the drain, and edgefall reads init's announcement itself when accessd doesn't answer. An update's
  reboot stays `updating`. With no answer and no announcement (accessd restarting) the last state
  stays.
- **Through the drain:** a reboot's or a shutdown's drain leaves edgefall running until the power
  goes ([init.md](init.md#the-service-table)), so once k0s has stopped, 443 still answers with the
  page.

## The poller

A product page includes it:

```html
<script src="/_box/poll.js" defer></script>
```

It asks `/_box/state` every second (each ask times out after 1.5 seconds). While the state isn't
`running`, it lays the branded page over the product (a closed shadow root, styled through the DOM,
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
| reboot or shutdown accepted, k0s still stopping | Traefik, `/_box/state` from edgefall | the overlay, within about 2 seconds |
| k0s stopped, the box still draining | edgefall | the overlay; a new visit gets the page |
| the power is off, firmware, early boot | nothing | the overlay, kept |
| booted, k0s not started | edgefall (`starting`) | the overlay |
| k0s starting, Traefik not bound yet | nothing (about a minute) | the overlay, kept |
| Traefik and the product back | Traefik | the page reloads into the product |
