# Certificates

The box keeps one certificate store for every TLS endpoint it hosts. An owner adds certificates to it
from the :8443 Certificates page (or `TlsService`, see [osadmin-api.md](osadmin-api.md#methods)) and
assigns one to each endpoint.

## Endpoints

| Endpoint | Answers on | Its certificate must cover | In this release |
|---|---|---|---|
| `admin` | :8443 on each management address | the host name or a management address | live |
| `product` | 443, every product route on one host | the box's names, as for `admin` | live once a product is installed ("Available when the product is installed" before) |

### The box's names

The names a certificate is checked against are the box's **host name** and its **management
addresses**. A certificate passes when it covers any one of them: covering the host name is enough,
and the certificate needn't list an address. The host name is a fully qualified name such as
`appliance.example.org`: the one set in the Hostname field on the :8443 Network page, or else the
one DHCP hands out (option 12, with option 15's domain added when the name has no dot). The box
never looks its own name up in DNS, so a box reached as `appliance.example.org` only knows that
name once it's set on Network or comes from DHCP. Setting it is a network change like any other: it
reverts unless confirmed, and the self-signed certificate is made again for the new name.

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
- The keys: KeyCustody sealed items `tls-<id>` (the box's own is `tls-self-signed`), so they leave
  the box only inside the encrypted escrow. Deleting a certificate or discarding a CSR overwrites its
  item with nothing.

## Expiry

Nothing renews an assigned certificate. Status and the page warn 30 days before it expires
(`WARNING_KIND_TLS_EXPIRING`), when it has expired (`WARNING_KIND_TLS_EXPIRED`, and it keeps
serving), and when it no longer covers any of the endpoint's names (`WARNING_KIND_TLS_NAMES`).
