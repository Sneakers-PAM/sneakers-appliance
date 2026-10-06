# Runbook: the production signing keys

An owner-only procedure. It names no secret value; the certificate fingerprints in
`keys/production/fingerprints.txt` are the public record.

There are four production keys, all generated fresh for this project, labelled production, and
never used by a lab or test build or shared with any other project:

| `production` environment secret | Key | Signs | Read by the release job |
|---|---|---|---|
| `SB_PK_KEY` | RSA-2048 | `PK.auth`, `KEK.auth` | only when a tag changes the committed KEK |
| `SB_KEK_KEY` | RSA-2048 | `db.auth`, `dbx.auth` | only when a tag changes the committed db or dbx |
| `SB_DB_KEY` | RSA-2048 | Authenticode on the UKI and systemd-boot | every tag |
| `RELEASE_COSIGN_KEY` and `RELEASE_COSIGN_PASSWORD` | cosign ECDSA P-256 (encrypted key file) | the `sneakers-os` artifact, `release.yaml`, the component images | every tag |

RSA-2048 because every UEFI implementation must accept it. The release key is separate so it can
rotate without touching firmware.

## Custody rules

- Each private key exists only as a secret of the GitHub `production` environment of
  Sneakers-PAM/sneakers-appliance. It's never stored in any other secret store, and never taken
  from a lab key or another project's key.
- The `production` environment has the owner as required reviewer and allows only `v*` tags
  ([repo-settings.md](../repo-settings.md)). Only the tag release workflow's `sign` job reads it.
- Inside that job the secrets are written to a tmpfs directory (mode 0600), used by the pinned
  `sbsign` and `cosign` only, and removed in an `always()` step. They're never passed on a command
  line, never written to the workspace and never uploaded.
- GitHub's deployment log for the environment is the audit trail of every use.

## 1. Generate the keys

On an offline-capable workstation, in an empty directory on a tmpfs:

```sh
umask 077
for role in PK KEK db; do
  openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 7300 \
    -subj "/CN=Sneakers-PAM Production Secure Boot ${role} 2026/" \
    -keyout "${role}.key" -out "${role}.crt"
done
cosign generate-key-pair --output-key-prefix release-cosign   # prompts for the password
```

Long validity is fine: firmware doesn't check db expiry.

## 2. Build and sign the enrolment material

```sh
guid=$(uuidgen)   # the signature owner, recorded in the lists
for role in PK KEK db; do cert-to-efi-sig-list -g "$guid" "${role}.crt" "${role}.esl"; done
: > dbx.esl
ts="$(date -u '+%Y-%m-%d %H:%M:%S')"
sign-efi-sig-list -t "$ts" -k PK.key  -c PK.crt  PK  PK.esl  PK.auth
sign-efi-sig-list -t "$ts" -k PK.key  -c PK.crt  KEK KEK.esl KEK.auth
sign-efi-sig-list -t "$ts" -k KEK.key -c KEK.crt db  db.esl  db.auth
sign-efi-sig-list -t "$ts" -k KEK.key -c KEK.crt dbx dbx.esl dbx.auth
for role in PK KEK db; do
  printf '%s %s\n' "$role" "$(openssl x509 -in "${role}.crt" -outform DER | sha256sum | cut -d' ' -f1)"
done > fingerprints.txt
printf 'release-cosign %s\n' "$(openssl pkey -pubin -in release-cosign.pub -outform DER | sha256sum | cut -d' ' -f1)" >> fingerprints.txt
```

## 3. Commit the public material

In a branch and PR of its own, copy only `PK.crt`, `KEK.crt`, `db.crt`, `PK.auth`, `KEK.auth`,
`db.auth`, `dbx.auth`, the four `.esl` files, `release-cosign.pub` (as `cosign.pub`) and
`fingerprints.txt` into `keys/production/`. A test in `🧪 Build & Test`
(`test/keys`) fails the PR if anything there is a private key.

## 4. Set the secrets, then wipe

Under Settings, Environments, `production`, set `SB_PK_KEY`, `SB_KEK_KEY` and `SB_DB_KEY` (the PEM
`.key` files), `RELEASE_COSIGN_KEY` (`release-cosign.key`) and `RELEASE_COSIGN_PASSWORD`. Then
unmount the tmpfs. The environment is now the only place the private keys exist.

## Rotation and loss

- **db or the release key:** make a new key and certificate, sign a new `db.auth` (or pin a new
  cosign public key) with KEK in CI, and ship it in a release; boxes enrol it through KEK. Add the
  old db certificate to dbx if it might be compromised.
- **KEK or PK:** a new key set, and a re-enrolment on every box, which the docs describe as a
  reinstall and restore.
- GitHub secrets can't be read back, so losing the environment loses the keys; recover as above.
- A suspected leak: rotate db through KEK, put the old db certificate in dbx, and pin a new release
  key in a new kit.
