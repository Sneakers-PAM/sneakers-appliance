# Certificates

The box keeps one certificate store for every TLS endpoint it hosts. An owner adds certificates to it
from the :8443 Certificates page (or `TlsService`, see [osadmin-api.md](osadmin-api.md#methods)) and
assigns one to each endpoint.

## Endpoints

| Endpoint | Answers on | Its certificate must cover | In this release |
|---|---|---|---|
| `admin` | :8443 on each management address | the host name or a management address | live |
| `product` | 443, every product route on one host | the product host | "Available when the product is installed" |

A management address here is the bare address (`192.0.2.10`), never the interface prefix netd
reports (`192.0.2.10/24`), and link-local addresses are left out. That's what a CSR names, what the
names check and Revert compare and what the :8443 check below connects to.

An endpoint's source is exactly one of an **assigned certificate** from the store or **cert-manager
(ACME)**. :8443 also has the box's own self-signed certificate, which it starts with and which
Revert to self-signed puts back. ACME answers `TLS_ACME_UNAVAILABLE` ("Not available yet") until the
product bundle brings cert-manager.

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
| names | its SANs cover the host name or a management address. A wildcard `*.domain` covers exactly one label |
| validity | today is between not-before and not-after |

## Applying

Assigning a certificate to `admin` writes `tls.crt` (the chain), `tls.key` and the marker
`tls.assigned` into `/var/lib/sneakers/osadmin/`, owned by the osadmin user. `sneakers-osadmin`
re-reads the files on the next handshake, so there's no restart, and keeps an assigned certificate
as it is when the host name or addresses change (Status then warns). accessd then connects to :8443
on each management address and compares the served certificate's fingerprint; if the new one isn't
served within 15 seconds, the previous files are put back (`TLS_NOT_SERVED`). Status, the console
and the `Endpoint` read the live file, so the fingerprint they show follows the swap. The store
takes one change at a time but keeps answering reads during that check, so Status and the console
stay live while a certificate is being applied; the endpoint shows its old assignment until the
check passes.

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
