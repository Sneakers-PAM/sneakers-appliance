# Network settings

netd owns the box's addresses, DNS, NTP and the management firewall. Its settings are set in the
first-boot network step and later on the :8443 Network page or with `network set`, and kept in
`/var/lib/sneakers/settings/network.yaml`.

## The settings

| Setting | Values | Default |
|---|---|---|
| Management interface | the NIC 22 and 8443 listen on | the first-boot choice |
| Service interface | optional second NIC for the product's 443 and 80; 22 and 8443 never listen there | none: one NIC carries both |
| IPv4 | `dhcp`, `static` (address with prefix length, optional gateway inside it) or `off` | `dhcp` |
| IPv6 | `slaac` (also reads RDNSS), `dhcpv6`, `static` (address with prefix length, gateway link-local or inside it) or `off` | `slaac` |
| Hostname | a fully qualified name such as `appliance.example.org` | from DHCP |
| DNS | up to 3 IPv4 or IPv6 addresses, and up to 6 search domains | from DHCP and RA |
| NTP | up to 4 addresses or host names | from DHCP (option 42, DHCPv6 option 56), else the public pool `0.pool.ntp.org` to `3.pool.ntp.org` | <!-- scrub:allow=fqdn -->
| Allow-list | the prefixes 22 and 8443 accept, without host bits | during setup any source on the management interface |
| Time zone | an IANA name such as `Europe/Paris`, or `UTC` | `UTC` |
| HTTPS proxy | an `http://` or `https://` URL without credentials | none |
| Cluster ranges | the k0s pod and service prefixes; they may not overlap each other or a static network of the box | `10.244.0.0/16` and `10.96.0.0/12`, the k0s defaults <!-- scrub:allow=private-ip --> |

At least one of IPv4 and IPv6 must be on for the management interface (and for the service interface
when there is one). A static IPv4 address can't be its subnet's network or broadcast address
(except on /31 and /32), and a static IPv6 address can't be link-local.

A setting that fails these rules is refused with `NET_INVALID`; the error names the field, such as
`management.ipv4.address` or `dns[1]`, and nothing is applied.

## Auto-revert

A change that leaves the interfaces, their addresses, the host name, the allow-list and the cluster
ranges alone (DNS servers, search domains, NTP servers, the time zone, the proxy) can't cut anyone
off, so it is applied and kept at once: no window, nothing to confirm, and `SetNetwork` returns an
empty token with `revert_after_seconds` 0 (the audit's `network.set` has `detail.kept: at-once`).

Any other change applies at once and waits 120 seconds for a confirmation from a session that still works
(the Network page, or the shell's `network set`, sends it). Without one, the previous settings are
applied again and the box records `NET_REVERTED`, so a change that cuts the admin off heals itself.
Only one change waits at a time: a second one is refused naming `pending` until the first is
confirmed or reverted. If applying a change fails outright, the previous settings are applied again
straight away and the error is returned.

Each change has an id (logs and audit) and a token (what `Confirm` takes). `Get` returns the
pending change's token, id and seconds left, and how the last change ended (`last`: confirmed or
reverted), so a page that was reloaded, or opened at the change's new address, can still confirm.
osadmin's `GetNetwork` passes the seconds left to every admin and the token to owners only.
`SetNetwork` says what the change moves: `moves_management` when the management interface or its
addressing changes, with `new_url` (`https://<address>:8443/`) when the change sets a static
address, and `new_certificate` when the host name or the address changes, so the box makes a new
self-signed :8443 certificate (unless an owner assigned one) and a browser that trusted the old one
asks again. The page then has to be opened at the new address, signed in again and the change
confirmed there within the window.

The audit has `network.set` and `network.confirm` with the change id in `detail.change`. A change
that reverts is recorded as `network.revert` (actor `netd`, code `NET_REVERTED`): osadmin asks
netd how the change ended a few seconds after its window, and again on the next `GetNetwork`, and
writes the entry once. A change undone at start (below) is written by netd itself, with
`detail.at: start`, since osadmin may not have been running inside its window. Both undo paths log
at error level, so they reach a production box's log.

Every page can show the window: `StatusService.GetStatus` carries `network_change` (`pending`,
`revert_seconds_left`, `change_id`, and `last_reverted`, `last_reverted_at_start`,
`last_change_id`) and a warning, `WARNING_KIND_NETWORK_PENDING` while a change waits and
`WARNING_KIND_NETWORK_REVERTED` once one was undone, which the console shows too.

The console's network editor changes only what it edits: it starts from the box's current settings
(`Get`), puts the static address on its family and, when one is typed, the DNS server, and keeps
NTP, the host name, the search domains, the allow-list, the time zone, the proxy and the cluster
ranges.

The window survives a restart: while a change waits, netd keeps the previous settings in
`network.prev.yaml` next to `network.yaml`. If netd stops or the box loses power inside the
window, the next start writes `network.prev.yaml` back to `network.yaml` and applies it, so an
unconfirmed change is undone, and says so: `Get`'s `last` has `reverted` and `at_start`, which
osadmin's `GetNetwork` passes on as `last_change_reverted` and `last_change_reverted_at_start`.
A confirmation counts only once `network.prev.yaml` is removed and the removal is synced to disk;
if it can't be removed, `Confirm` fails and the change stays pending, so the page never says
"Confirmed" for a change the next start would undo. Every write and removal under `settings/` is
synced (the file, then its directory).

## What is kept where

Every setting an admin makes lives on the encrypted state volume, `/var/lib/sneakers`, which a
reboot, a base update (the other root slot), a product update and a revert all leave alone:

| Setting | File |
|---|---|
| Network (addresses, host name, DNS, NTP, allow-list, time zone, proxy, cluster ranges) | `settings/network.yaml` (and `settings/network.prev.yaml` while a change waits) |
| Update mode, window and mirror | `osadmin-api/upgrade-policy.json` |
| The mirror's CA or pin | `osadmin-api/update-trust.json` |
| Access policy (lockout, root-shell lifetimes, SSH key validity) | `access/` (the access store) |
| TLS certificates and endpoint assignments | `osadmin-api/tls/store.json`, the keys sealed in KeyCustody; the :8443 files and their `tls.assigned` marker in `osadmin/` |
| The clock floor | `netd/clock-floor` |

The 22 and 8443 open/closed state follows the setup steps and is kept in `/run`, so it is
rebuilt at each boot.

## sneakers-netd

`sneakers-netd` runs as root in first boot and normal operation (`os/rootfs/services.d/netd.yaml`,
readiness `/run/sneakers/netd.ready`; init restarts it whenever it stops, and the addresses stay in
the kernel meanwhile). It serves `sneakers.appliance.netd.v1.NetworkService` on
`/run/sneakers/netd.sock` to root peers only (`SO_PEERCRED`); osadmin and the closed shell reach it
through accessd. Go callers use `internal/netdapi` (`netdapi.SocketPath`, `netdapi.NewClient`).
Flags: `--state` (`/var/lib/sneakers`), `--run` (`/run/sneakers`), `--socket`.

Until the first-boot network step sets anything, netd runs the screen's defaults on the first NIC
with a link, else the first NIC: DHCP for IPv4 and SLAAC for IPv6. Nothing is written to
`network.yaml` until a `Set`.

A NIC is an interface with a device on a bus, `/sys/class/net/<if>/device` (PCI, virtio, USB).
Loopback, dummy, bridge, veth, tun/tap, vxlan and WireGuard interfaces have none, and neither do
the ones k0s and the CNI make (`sneakers0`, `cni0`, `kube-bridge`, `veth*`), so netd never takes
one for the management or service interface, whatever its name. The NICs are ordered by their
device path under `/sys/devices` (bus order), then by MAC, so the choice is the same on every boot
even when the kernel names the interfaces differently.

| Call | What it does |
|---|---|
| `Get` | the applied settings, and whether a change waits for `Confirm` |
| `Set`, `Confirm` | apply a change, and keep it (see [Auto-revert](#auto-revert)); an interface the box doesn't have, or a virtual one, is `NET_INVALID` naming `management.name` or `service.name` |
| `Checks` | the connectivity checks below |
| `Status` | the usable management and service addresses, the host name, the NTP sync and offset, and whether 22 and 8443 are open |
| `ListInterfaces` | the NICs in bus order (virtual interfaces left out): name, MAC, link state and driver |
| `SetManagementPorts` | opens or closes 22 and 8443 in the firewall (first boot) |
| `SetServicePorts` | the product's accept rules on the service interface, or the management one when the box has only one (spec 3 defines them; netd carries them, in memory). accessd sets 80 and 443 once a product bundle is installed ([k0s.md](k0s.md)) |
| `Watch` | a stream of the usable addresses and the host name: once at the start, then on every change |

### Addresses

netd applies the settings over rtnetlink, interface by interface and family by family; a change
that leaves a family's settings alone (only the DNS servers, say) leaves its addresses and clients
running, so a lease isn't dropped under an admin's session.

- **IPv4 DHCP:** a DHCPv4 client (`github.com/insomniacslk/dhcp`, BSD-3-Clause) asks for the
  address, router, DNS servers, NTP servers (option 42), host name, domain and search list. The
  address carries the lease's lifetime, it renews at T1 (then every 30 seconds until the lease
  ends), and a lost lease removes the address and its default route.
- **IPv6 SLAAC:** the kernel makes the addresses and the default route from router advertisements
  (`accept_ra=2`, since k0s turns forwarding on, and `autoconf=1`). netd reads the advertisements
  too (`github.com/mdlayher/ndp`, MIT) for their RDNSS and DNSSL options, and when the router sets
  the O flag it sends a stateless DHCPv6 information request for the NTP servers (option 56).
- **IPv6 DHCPv6:** a stateful DHCPv6 client asks for an address (a /128 with the server's
  lifetimes), DNS, search list and NTP; the default route still comes from router advertisements.
- **Static:** the address and the default route are set as given; every other global address of
  that family on the interface is removed.
- **Off:** the family's addresses and default route are removed (IPv6 off sets `disable_ipv6`).

Default routes have metric 100 on the management interface and 200 on the service interface.

### DNS, NTP and the host name

The settings win where they say something; otherwise netd uses what DHCP and router advertisements
offer, management interface first. `/run/sneakers/resolv.conf` (which `/etc/resolv.conf` links to)
lists at most three servers, link-local ones left out, and at most six search domains. The host
name is the setting, else the DHCP host name joined to its domain. The kernel always has a host
name: init sets it once the state is open, before any service starts, to the setting or else the
box's own name, and netd keeps it current from then on (the setting, else the DHCP name, else the
box's own name). The box's own name, `sneakers-<8 hex>`, is made once from random bytes and kept on
the state volume in `/var/lib/sneakers/box-name`; it is also the k0s node name
([k0s.md](k0s.md#the-nodes-address-and-name)). It only names the kernel: the box's host name for
certificates, `Status` and `Watch` stays the setting or the DHCP name, and is empty without one. With no DNS server set or
offered the file names none, and the box still runs; k0s's cluster DNS falls back as
[k0s.md](k0s.md#cluster-dns-with-no-dns-server) describes.

### The host name

The host name is never baked into the product bundle: one bundle fits every box, and each box gives
the product its own name.

- **At deploy.** The OVA offers two vApp properties, **Host name** (`hostname`) and **Domain**
  (`domain`), which vCenter asks for when it deploys the OVA. vCenter hands them to the VM in an
  `ovf-env.xml` on an ISO in its CD drive (the OVF `iso` transport); at first boot, while the box has
  no network settings yet, netd reads it (`internal/ovfenv`) and the first-boot settings take the
  name: a fully qualified host name as it is, a short one joined to the domain, or the box's own name
  joined to the domain when only the domain is set. A short name with no domain isn't a host name
  setting and is ignored (netd logs it). The first-boot screen starts from those settings, so setting
  up keeps the name. Once the box has settings the properties are never read again. The ESXi host
  client and other hypervisors have no vApp properties: the box then names itself
  `sneakers-<8 hex>` until the host name is set.
- **Later.** The console shows the host name, and the :8443 Network page's Hostname field edits it.
  A host name change waits 120 s for its confirm like an address change, and reverts without one.
- **The product.** The box's FQDN for the product (`box.fqdn`, `internal/boxvalues`) is the host name
  above, else the first management address, else the box's own name. A product bundle's stacks
  carry a placeholder where the host goes (product.yaml `box_values`,
  [release.md](release.md#productyaml)); the box puts its FQDN in its place whenever it puts a stack
  in front of k0s (`k0s-interim` at each k0s start, the MCP switch when it turns on). Each product
  apply and revert records the FQDN in `/var/lib/sneakers/platform/box-values`. When the host name
  changes, accessd applies the product again with the new FQDN once the change is kept (confirmed,
  or a DHCP name), under the same maintenance gate as an update; the Updates history shows it as an
  apply of the same version with `host name <fqdn>`, audited as `upgrade.apply` with the surface
  `hostname`. A change that waits for its confirm doesn't reach the product, and a reverted one
  never does. The Sneakers sign-in (Kratos's URLs and return URLs, the WebAuthn relying party),
  the SSH websocket, and the MCP, OAuth and Hydra addresses all follow it.
- **The OAuth issuer** is `https://<fqdn>/oauth`, on the same name and certificate as everything
  else on 443; no `hydra.<fqdn>` name is needed. The edge routes `/oauth/` to Ory Hydra's public
  port and strips the prefix (its `oauth-prefix` middleware), and Hydra builds its URLs from
  `https://<fqdn>/oauth/`: discovery at `/oauth/.well-known/openid-configuration`, its keys at
  `/oauth/.well-known/jwks.json` and tokens at `/oauth/oauth2/token`. The gateway checks a machine
  token's issuer against `https://<fqdn>/oauth`. The MCP's own sign-in stays at the root: the
  gateway's `/.well-known/oauth-authorization-server` (issuer `https://<fqdn>`) and `/oauth2/`,
  which the `/oauth/` route never takes. All of it runs only while the MCP switch is on.
- **The 443 certificate** must cover the host name, not only an address: the product endpoint warns
  (`names-not-covered`, and a Status warning on every :8443 page) when its certificate doesn't,
  naming the host name and what the certificate covers. A wildcard for the host name's domain
  (`*.example.org` for `sneakers.example.org`) covers it.

The clock is kept by SNTP (`internal/timesync`, IPv4 and IPv6 servers, up to
four): one bounded sync, then polls. The servers are the settings', else
DHCP's, else the image's default pool (`0.pool.ntp.org` to `3.pool.ntp.org`), <!-- scrub:allow=fqdn -->
so a box on a network that names none still gets the time; naming servers in
the settings replaces the pool. `Status` (and `GetNetwork`) list the servers in use as
`ntp_servers`, and what DHCP and router advertisements gave as `learnt_dns`,
`learnt_search` and `learnt_ntp`, which the Network page shows next to the
typed values.

An offset up to 128 ms is slewed. A larger one is stepped at the boot sync and
whenever the clock is behind. A clock ahead of the servers on a running box
(one that booted a few seconds fast and missed the boot sync) is slewed back
when it's up to 30 seconds ahead, so it never runs backwards, and stepped back
beyond that. Every step is audited as `clock.step` (actor `netd`, with the
server, `offsetMs` and whether it was the boot sync). The clock is never
stepped behind its floor (`/var/lib/sneakers/netd/clock-floor`, never earlier
than the image's build time).

### The checks

`Checks` runs on the management interface and reports each as `ok`, `warn` or `failed`, with the
`NET_*` code when it isn't ok:

| Check | ok when | otherwise |
|---|---|---|
| `link` | the NIC has a carrier | `failed`, `NET_NO_ADDRESS` |
| `address` | each enabled family has a usable address (IPv6 DAD finished; the check waits up to 3 s for it) | no address at all: `failed`, `NET_NO_ADDRESS`, the one check setup can't skip; one family missing: `warn`, `NET_DHCP_TIMEOUT` |
| `gateway` | each family's default gateway answers ARP or neighbour discovery | none known: `warn`; no answer: `failed`; both `NET_GATEWAY` |
| `dns` | each DNS server answers a query for the first NTP host name (or `example.org`) | `failed`, `NET_DNS`; no server at all: `warn` |
| `ntp` | the clock synced; the detail gives the server and the offset | unsynced: `failed`; no server: `warn`; both `NET_NTP` |

Every check except `address` with no address at all is skippable: the first-boot screen offers
**Edit** or **Continue anyway**.

### The management firewall

netd writes one nftables table, `inet sneakers_mgmt` (`github.com/google/nftables`, Apache-2.0;
there's no `nft` binary on the box), whose `input` chain runs at priority -10, before the k0s
network stack's filter chains. The whole table is replaced in one netlink transaction on every
change:

1. established and related traffic is accepted;
2. 22 and 8443 are accepted on the management interface only, and only once the first-boot step
   that opens them has called `SetManagementPorts` (22 at the SSH step, 8443 at the recovery-key
   step). Once `/var/lib/sneakers/setup/done` exists both stay open. The choice is kept in
   `/run/sneakers/netd/ports.json`, so it lasts until the next boot;
   once open, each is also accepted on `lo`. A connection from the box to one of its own
   addresses arrives on `lo`, not on the NIC holding the address, and only the box can send on
   `lo`, so this opens nothing to the network. The certificate swap's self-test needs it: it dials
   the box's own management addresses on 8443 ([certificates.md](certificates.md));
3. with an empty allow-list (first boot's default) any source on the management interface is
   accepted; otherwise only the allow-list's prefixes (IPv4 and IPv6 interval sets, `allow4` and
   `allow6`), and a family with no prefix has no way in;
4. the product's service-interface rules from `SetServicePorts`;
5. every other packet to 22 or 8443 is dropped. Other ports are left alone.

### Address events

netd watches the kernel's address, link and route notices. Whenever the usable addresses change
(no link-local address, none still in DAD or failed it), `Watch` sends the new list, so sshd and
osadmin rebind (a DHCP renewal to a new address, an IPv6 privacy address rotation).

### Tests

The unit tests run netd against a fake kernel. The network-namespace tests run the real netd
(rtnetlink, sysctls, nftables, the DHCP and RA clients) inside a namespace, against a router
namespace that serves DHCPv4, DHCPv6, router advertisements with RDNSS, DNS and SNTP from the same
libraries: DHCPv4, SLAAC with RDNSS on an IPv6-only network, stateful DHCPv6, dual stack, static,
and an address change reaching `Watch`. The firewall's tests connect from a second namespace: 22 and
8443 answer only from the allow-list, only on the management interface, and only once opened. The
box namespace also dials its own management addresses, which must connect once the port is open. They
need root and skip without it; CI runs them as root (`SNEAKERS_REQUIRE_NETNS=1`).
