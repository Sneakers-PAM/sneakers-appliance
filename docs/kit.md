# sneakers-kit

`sneakers-kit` verifies an org-signed appliance release and builds install media from it. It never
signs anything and holds no private key.

## Pins

Each kit is built with the keys it trusts stamped in through `-ldflags -X` on
`github.com/Sneakers-PAM/sneakers-appliance/internal/release`:

| Variable | Value |
|---|---|
| `Channel` | `production` or `lab` |
| `ReleaseKey` | base64 of the cosign public key (PEM) |
| `DBCert`, `PKCert`, `KEKCert` | base64 of the Secure Boot db, PK and KEK certificates (PEM) |
| `Version` | the kit version |

A kit with any pin missing or undecodable, or a channel other than `production` or `lab`, refuses
to start with `KIT_PIN_MISSING`. A lab kit (built in pull-request CI with that run's throwaway keys)
refuses a production release with `KIT_CHANNEL`, and a production kit refuses a lab release.

## Commands

```
sneakers-kit verify <ref> [--arch amd64|arm64] [--plain-http]
sneakers-kit build  <ref> --format iso|ova|qcow2|rpi|raw [--arch amd64|arm64] [--disk-size 64G] [--out DIR] [--plain-http]
sneakers-kit version
sneakers-kit backup
```

- `verify` runs the whole chain ([artifact.md](artifact.md)) on a private copy in a temporary
  directory, prints `verified <version> <arch> (<channel>)` and removes the copy. It writes
  nothing else.
- `build` resolves `<ref>` to a digest once, fetches that digest (with its signature) into a
  temporary directory inside `--out`, verifies the copy, and gives the same copy to the format's
  writer. The output is moved into `--out` only when every step succeeded; a refused or failed
  build leaves `--out` as it was. A tag moved after the resolve changes nothing. Outputs are named
  `sneakers-<version>-<arch>`, with `-LAB` for a lab release. Formats arrive with their writers;
  a kit refuses a format it doesn't carry.
- `version` prints the kit version, its channel and the SHA-256 fingerprint of each pin.
- `backup` is the group for working with exported backup sets off the box. It has no commands yet
  and prints its usage.

`<ref>` is one of:

| Form | Meaning |
|---|---|
| a directory | an OCI layout, for offline sites |
| `sneakers-os:<version>` | `ghcr.io/sneakers-pam/sneakers-os:<version>` |
| `sha256:<hex>` | that digest in `ghcr.io/sneakers-pam/sneakers-os` |
| `<registry>/<repository>:<tag>` or `@sha256:<hex>` | any registry |

`--plain-http` talks HTTP instead of HTTPS, for a lab registry on loopback. Logs go to stderr
(`LOG_LEVEL`, `LOG_FORMAT`; console and info by default); results go to stdout.

## The appliance manifest

Every release carries one `appliance.yaml` per architecture (spec 1, Section 4.1). The kit decodes
it strictly: an unknown field, a missing Secure Boot file on amd64, a Secure Boot block on arm64, or
`upgradeFrom` above `version` is refused with `KIT_MANIFEST_INVALID`. Then it checks:

- `metadata.channel` equals the kit's channel (`KIT_CHANNEL`);
- `spec.kitMin` is at most the kit's version, compared as semantic versions (`KIT_KIT_TOO_OLD`);
- the PK, KEK and db fingerprints equal the kit's pins (`KIT_WRONG_SIGNER`).

## Error codes

The kit exits non-zero and prints `SYMBOL (code): sentence`. The codes are listed in
[errors.md](errors.md).
