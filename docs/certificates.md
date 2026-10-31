# Certificates

The box keeps one certificate store for every TLS endpoint it hosts. An owner adds certificates to it
from the :8443 Certificates page (or `TlsService`, see [osadmin-api.md](osadmin-api.md#methods)) and
assigns one to each endpoint.

## Endpoints

| Endpoint | Answers on | Its certificate must cover | In this release |
|---|---|---|---|
| `admin` | :8443 on each management address | the host name or a management address | live |
| `product` | 443, every product route on one host | the box's names, as for `admin`; it warns unless it covers the host name, which the product's URLs use ([network.md](network.md#the-host-name)) | live once a product is installed ("Available when the product is installed" before) |

### The box's names

The names a certificate is checked against are the box's **host name** and its **management
addresses**. A certificate passes when it covers any one of them: covering the host name is enough,
and the certificate needn't list an address. The host name is a fully qualified name such as
`appliance.example.org`: the one set in the Hostname field on the :8443 Network page, or else the
one DHCP hands out (option 12, with option 15's domain added when the name has no dot). The box
never looks its own name up in DNS, so a box reached as `appliance.example.org` only knows that
name once it's set on Network or comes from DHCP. Setting it is a network change like any other,
and the self-signed certificate follows the new name once the change is kept
([Following the box](#following-the-box)).

With no host name, the box can only check its addresses, so a wildcard such as `*.example.org` is
refused with `TLS_NO_HOSTNAME`, which says to set the host name first. The Certificates page shows
the names the box checks, and when there's no host name a notice links to Network. The same names
go into every CSR and into the `admin` endpoint's state. A CSR made while the box has no host name
also names the box's own name (`sneakers-<8 hex>`, the name the console shows), as a DNS SAN and
its common name.

A management address here is the bare address (`192.0.2.10`), never the interface prefix netd
reports (`192.0.2.10/24`), and link-local addresses are left out. That's what a CSR names, what the
names check and Revert compare and what the :8443 check below connects to.

An endpoint's source is exactly one of an **assigned certificate** from the store or **cert-manager
(ACME)**. Both endpoints also have the box's own self-signed certificate, which they start with and
which Revert to self-signed puts back. ACME answers `TLS_ACME_UNAVAILABLE` ("Not available yet")
until the box drives the product bundle's cert-manager.

## Adding a certificate

In the order the page offers them:

1. **Upload PFX** (the main path): one `.pfx` / `.p12` with the certificate (a wildcard works), its
   private key and the full chain, and its password. The password is used for the import only and
   never stored; the key is sealed through KeyCustody and the PFX file itself is never kept.
2. **Upload PEM:** the certificate, the private key and the chain.
3. **Create a request on this box (CSR):** for a single-name certificate. The box makes the key (RSA
   4096 by default; RSA 3072, ECDSA P-256 or P-384) and seals it, then returns a CSR for that one name
   plus the host name and the management addresses. Wildcard names are refused, since a wildcard key
   is shared across servers: import it with Upload PFX. Upload the signed certificate and its chain
   for the CSR. Up to eight CSRs may be pending.

Every way in is checked before anything is stored, and a refusal names the first failure
([errors.md](errors.md#certificates-38xx)):

| Check | Passes when |
|---|---|
| key | the certificate is for the CSR's key, or for the uploaded key; RSA 3072 or more, or ECDSA P-256 or P-384 |
| usage | a TLS server certificate, not a CA |
| chain | it builds to a root: a self-signed certificate in the chain, or the root uploaded on its own. A missing link is named |
| names | its SANs cover the host name or a management address (either one is enough). A wildcard `*.domain` covers exactly one label. A refusal lists the names the box checked and the names the certificate covers; with no host name it is `TLS_NO_HOSTNAME` |
| validity | today is between not-before and not-after |

## Applying

Assigning a certificate to `admin` writes `tls.crt` (the chain), `tls.key` and the marker
`tls.assigned` into `/var/lib/sneakers/osadmin/`, owned by the osadmin user. `sneakers-osadmin`
re-reads the files on the next handshake, so there's no restart, and keeps an assigned certificate
as it is when the host name or addresses change (Status then warns). accessd then connects to :8443
on each management address and compares the served certificate's fingerprint; if the new one isn't
served within 15 seconds, the previous files are put back (`TLS_NOT_SERVED`). The box's connection
to its own address comes in on `lo`, which the management firewall accepts for 22 and 8443 once
they're open ([network.md](network.md#the-management-firewall)). Status, the console
and the `Endpoint` read the live file, so the fingerprint they show follows the swap. The store
takes one change at a time but keeps answering reads during that check, so Status and the console
stay live while a certificate is being applied; the endpoint shows its old assignment until the
check passes.

Assigning a certificate to `product` keeps it on the state volume
(`/var/lib/sneakers/platform/tls/product.{crt,key}`, root only) and writes the `box-tls` stack k0s
applies (`/var/lib/k0s/manifests/box-tls/`, `internal/productedge`): the Secret `box-tls` in
`sneakers-edge` with the chain, the key and `traefik-tls.yaml`, a Traefik dynamic config that makes
them the default certificate. The edge mounts that file next to its routes in one projected
directory, which Traefik's file provider watches, so the new certificate is served as soon as the
kubelet updates the volume (up to a minute), with no restart. accessd then connects to
`127.0.0.1:443` and compares the served fingerprint; if the new certificate isn't served within 3
minutes, the previous pair is put back (`TLS_NOT_SERVED`). Revert to self-signed on `product`
drops the assigned pair and the edge goes back to the box's own certificate, the one :8443 has,
checked the same way. At every k0s start `k0s-interim` writes the same stack from the assigned pair
when there is one, else from :8443's. Every assignment and revert is audited (`tls.endpoint.assign`,
`tls.endpoint.revert`), as for `admin`.

## Following the box

The box's own self-signed certificate follows its host name and management addresses, with no
admin action, whether they changed by a static change or a DHCP lease. `sneakers-osadmin` only
serves the files and makes the first certificate; accessd does the following, because only it knows
whether a change is kept. It looks at start, on every netd address or host name event, after a
confirm, and every minute.

| What happened | What the certificate does |
|---|---|
| Static change or host name, committed | Replaced once the names have held still for 30 seconds |
| DHCP lease moves, nobody watching | The same: there's no pending change to wait for |
| A change waits for its confirm, or is being applied or undone | Stays. Replaced 30 seconds after it's kept; never touched if it reverts, so there's nothing to put back |
| A change undone at start (`network.prev.yaml`) | Stays: the box comes back on the names it already covers |
| netd doesn't answer | Stays, looked at again each minute: nobody can say the change is kept |
| Addresses come back one at a time after a boot | One certificate for the set they settle on. A certificate that names more addresses than the box has now stays, so a normal reboot changes nothing |
| An address goes and comes back within the 30 seconds | Stays |
| The box's names return to what an earlier certificate named | That certificate comes back, with its key and fingerprint, while it has more than 30 days left |
| Within 30 days of its end | Renewed at the next look, with no settling time |
| An owner assigned a certificate | Never replaced. When it no longer covers the names, `names-not-covered` says so |
| No address at all | Stays |

The fingerprint an admin checked on the console only changes for one of these reasons. Before the
old certificate is replaced its key is sealed (`tls-self-signed-previous`); if that can't be done the
certificate stays and the follower tries again each minute, since replacing it would lose that
fingerprint for good.

Each change is audited as `tls.selfsigned.replace` (actor `box`), with `detail.old`, `detail.new`,
`detail.reason` (`addresses`, `hostname`, `expiring`, or `edge-behind` when only 443 caught up),
`detail.restored` and `detail.endpoints`. For 7 days Status carries it as `tls_change` with
`WARNING_KIND_TLS_CHANGED`, which the console and the :8443 pages show. The console's fingerprint
is always the live one.

443 and edgefall keep copies. Where 443 serves the box's own certificate, accessd rewrites the
`box-tls` stack in the same step, so Traefik reloads it within about a minute; it checks that stack on
every look, so one that fell behind catches up. edgefall gets its copy too, and uses it the next
time it takes 443 while k0s is down. A certificate assigned to `product` is left alone. An
address-only change with a host name set changes nothing the product depends on: its URLs use the
name, so with an assigned certificate there's nothing to do but keep DNS right. With no host name
the product's address is the box's first management address, so it's applied again with the new one
([network.md](network.md#the-host-name)). The box's own certificate names management addresses only:
a browser that opens 443 on a service interface's address always gets a name warning, so use the
host name there.

## Update trust

The update mirror's own trust, kept apart from the store: one or more private CA certificates
(PEM) an `https://` update mirror may chain to, and an optional SHA-256 pin on the mirror's server
certificate (`TlsService.SetUpdateTrust` and `ClearUpdateTrust`, owner). The CAs are trusted for
the mirror's fetches only; nothing else on the box uses them. Only CA certificates valid now are
taken, at most 8. `GetCertificateStore.update_trust` lists them (subject, issuer, expiry,
fingerprint) with the pin. See [upgrades.md](upgrades.md#an-internal-mirror).

## Where things live

- The store: `/var/lib/sneakers/osadmin-api/tls/store.json` (root only): the certificates and chains,
  the pending CSRs and the assignments. No keys.
- The keys: KeyCustody sealed items `tls-<id>` (the box's own is `tls-self-signed`, the one before it
  `tls-self-signed-previous`), so they leave
  the box only inside the encrypted escrow. Deleting a certificate or discarding a CSR overwrites its
  item with nothing.

## Expiry

The box renews its own certificate ([Following the box](#following-the-box)). Nothing renews an
assigned certificate. Status and the page warn 30 days before it expires
(`WARNING_KIND_TLS_EXPIRING`), when it has expired (`WARNING_KIND_TLS_EXPIRED`, and it keeps
serving), and when it no longer covers any of the endpoint's names (`WARNING_KIND_TLS_NAMES`).
