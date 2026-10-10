# The internal update mirror

An air-gapped site can still fetch updates from a web server of its own: the update policy's
mirror (`UpgradePolicy.mirror_url`) is that server. This note is the design; how to set one up is
in [upgrades.md](upgrades.md#an-internal-mirror).

## What it is

- **One source, in the policy.** The source is a setting of the update policy (owner,
  `UpgradePolicy.source`), not a choice made per download:
  - `builtin`: the list compiled into the signed root for the build's channel, walked in order.
    A production build's list is the project's GitHub Releases, read for the box's channel
    ([upgrades.md](upgrades.md#the-github-source)); a lab build's is the lab mirror the build
    names (`release.Mirrors`), or the test repository its policy names (`release_repo`, lab
    builds only).
  - `manual`: the mirror URL (`mirror_url`).
  - `none`: upload only. The box never makes a network fetch (`UPGRADE_AIR_GAPPED`).

  A policy from before the source reads as one: a set mirror URL is `manual`, `direct` on with no
  mirror is `builtin`, neither is `none`. Until the owner saves it with a source, a policy with
  both a mirror and `direct` keeps its old order, the mirror then the release source.
- **`http://` or `https://`.** The URL has a host, no user name or password and no query; the
  box adds the file name to it.
- **Integrity never depends on the transport.** Every `.bin` is checked against the release key,
  the channel and the header's hash before anything is decrypted or unpacked, whichever way it
  came. The product index is only a menu either way. Plain HTTP gives the integrity of the
  signature and nothing else: the fetch can be watched or blocked, not changed undetected.

## Trust for an HTTPS mirror

- **The system roots by default.** A mirror with a certificate from a public CA needs nothing
  more. The root image carries no CA bundle, so accessd uses Go's embedded copy of the Mozilla
  roots (`golang.org/x/crypto/x509roots/fallback`); the release source is checked the same way.
- **A private CA, for the mirrors only** (the manual one and the built-in list's). An owner adds the internal CA (one or more PEM CA
  certificates) on the Certificates page (`TlsService.SetUpdateTrust`). The box adds it to the
  roots of the mirror's fetches and of nothing else: not the release source, not :8443, not the
  product. It's kept in `/var/lib/sneakers/osadmin-api/update-trust.json` and read on every fetch,
  so a change takes effect at once. Only CA certificates (basic constraints CA:TRUE) that are valid
  now are taken.
- **An optional pin.** With it, the mirror's server certificate must also have that SHA-256
  fingerprint (hex, with or without colons, any case). The pin is checked after the chain, never
  in place of it.
- **Never a skip-verify.** There is no setting that turns verification off. A certificate that
  doesn't chain to the roots or doesn't name the host is refused (`UPGRADE_MIRROR_UNTRUSTED`), and
  a pin that doesn't match is refused (`UPGRADE_MIRROR_PIN`). Both refusals name the presented
  certificate's fingerprint and issuer, so the owner can compare it with the server's. A redirect
  that changes the scheme is refused too.

## What the owner sees

- `GetUpgrades.mirror_status`: the source and the URL it's about (with the built-in list, the entry
  last fetched from, and the whole list), the scheme, whether a private CA and a pin are set, and
  the last fetch: when, its result and code, and for HTTPS the server certificate's subject, issuer,
  expiry, fingerprint and whether the pin matched. For HTTP it says "plain HTTP: integrity from
  the signature only". It's kept in memory, so after a restart it reads "not checked yet" until
  the next fetch (Check now on Updates is one).
- `GetCertificateStore.update_trust`: the CAs (subject, expiry, fingerprint) and the pin.

## Logging and audit

Each fetch attempt, of the index or a `.bin`, from the mirror or the release source, is logged
(the URL, the source, the result or code and the duration) and written to the OS audit log as
`upgrade.source.fetch`, with the same details and the admin who asked. URLs never carry
credentials, because the policy refuses them.

