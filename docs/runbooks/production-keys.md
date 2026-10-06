# Runbook: the production keys

An owner-only procedure. It names no secret value; the certificate and key fingerprints in
`keys/production/fingerprints.txt` are the public record.

There are five production keys, all generated fresh for this project, labelled production, and
never used by a lab or test build or shared with any other project. Four sign; the fifth, the
update key, is what every release's `.bin` is encrypted to ([release.md](../release.md)):

| `production` environment secret | Key | Signs | Read by the release job |
|---|---|---|---|
| `SB_PK_KEY` | RSA-2048 | `PK.auth`, `KEK.auth` | only when a tag changes the committed KEK |
| `SB_KEK_KEY` | RSA-2048 | `db.auth`, `dbx.auth` | only when a tag changes the committed db or dbx |
| `SB_DB_KEY` | RSA-2048 | Authenticode on the UKI and systemd-boot | every tag |
| `RELEASE_COSIGN_KEY` and `RELEASE_COSIGN_PASSWORD` | cosign ECDSA P-256 (encrypted key file) | the `sneakers-os` artifact, `release.yaml`, the `.bin` header, and every image in the bundle, third-party ones included | every tag |
| none (see below) | the update key, age X25519 | nothing: the `.bin` payload is encrypted to its public half, `update.pub` | never; encrypting needs only `update.pub` |

RSA-2048 because every UEFI implementation must accept it. The release key is separate so it can
rotate without touching firmware.

## Lab and production never cross

Every key here has a lab twin that `build/keys/lab-keys.sh` makes fresh for each CI run, labelled
`LAB ephemeral NOT FOR PRODUCTION`, on a tmpfs that's unmounted at the end of the job. A lab build
pins the lab keys and a production build the production ones, so a production box refuses a lab
`.bin` (`UPGRADE_CHANNEL`) and a lab box refuses a production one. The release workflow's `sign`
job runs `build/release/check-fingerprints.sh` and refuses to sign unless every certificate and
`update.pub` match `fingerprints.txt`, and it checks each private key belongs to its committed
public half before using it.

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
age-keygen -o update.key
age-keygen -y update.key > update.pub
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
printf 'update-recipient %s\n' "$(grep -v '^#' update.pub | tr -d '\n' | sha256sum | cut -d' ' -f1)" >> fingerprints.txt
```

## 3. Commit the public material

In a branch and PR of its own, copy only `PK.crt`, `KEK.crt`, `db.crt`, `PK.auth`, `KEK.auth`,
`db.auth`, `dbx.auth`, the four `.esl` files, `release-cosign.pub` (as `cosign.pub`), `update.pub`
and `fingerprints.txt` into `keys/production/`. A test in `🧪 Build & Test`
(`test/keys`) fails the PR if anything there is a private key, including an age identity.

## 4. Set the secrets, then wipe

Under Settings, Environments, `production`, set `SB_PK_KEY`, `SB_KEK_KEY` and `SB_DB_KEY` (the PEM
`.key` files), `RELEASE_COSIGN_KEY` (`release-cosign.key`) and `RELEASE_COSIGN_PASSWORD`. Then
unmount the tmpfs. The environment is now the only place the signing keys exist.

`update.key` isn't a GitHub secret: the release job never decrypts, so it doesn't need it. Every
production box needs it to decrypt a `.bin`, so copy it to the owner's offline storage before the
tmpfs is unmounted, and keep it there until the box's copy is provisioned.

## Rotation and loss

- **db or the release key:** make a new key and certificate, sign a new `db.auth` (or pin a new
  cosign public key) with KEK in CI, and ship it in a release; boxes enrol it through KEK. Add the
  old db certificate to dbx if it might be compromised.
- **KEK or PK:** a new key set, and a re-enrolment on every box, which the docs describe as a
  reinstall and restore.
- **The update key:** a new key pair and its `update.pub` and fingerprint committed; every box
  must hold the new private half before the first `.bin` encrypted to it ships.
- GitHub secrets can't be read back, so losing the environment loses the keys; recover as above.
- A suspected leak: rotate db through KEK, put the old db certificate in dbx, and pin a new release
  key in a new kit.
