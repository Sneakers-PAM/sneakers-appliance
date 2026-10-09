# Production public keys

The owner commits the production public material here, following
[docs/runbooks/production-keys.md](../../docs/runbooks/production-keys.md). Never a private key; a
test fails the build if one appears.

## Expected files

[`expected-files.txt`](expected-files.txt) is the list the release job checks; all of them are
public:

| File | What it is |
|---|---|
| `PK.crt`, `KEK.crt`, `db.crt` | the Secure Boot certificates (PEM, self-signed, RSA-2048) |
| `PK.esl`, `KEK.esl`, `db.esl`, `dbx.esl` | their EFI signature lists (`dbx.esl` is empty) |
| `PK.auth`, `KEK.auth`, `db.auth`, `dbx.auth` | the signed variables a box enrols |
| `cosign.pub` | the release key's public half |
| `update.pub` | the update key's age recipient, with its label line |
| `fingerprints.txt` | the SHA-256 record of the certificates, `cosign.pub` and `update.pub` |

The matching secrets in the `production` environment are `SB_DB_KEY`, `RELEASE_COSIGN_KEY`,
`RELEASE_COSIGN_PASSWORD` and `UPDATE_AGE_KEY`. The PK and KEK private keys are kept offline only.

## Rules the release job enforces

`build/release/check-production-keys.sh` runs in the release guard and again before the sign
job signs, and refuses the set unless:

- every expected file is here;
- each certificate's CN says `Production` and names its role (`PK`, `KEK`, `db`), and never says
  lab, test, ephemeral or dev: for example `Sneakers-PAM Production Secure Boot db 2026`;
- each certificate is self-signed with an RSA-2048 key;
- every label line in `update.pub` says `Production`;
- `fingerprints.txt` matches the files (`build/release/check-fingerprints.sh`);
- no certificate or key is in [`build/keys/lab-fingerprints.txt`](../../build/keys/lab-fingerprints.txt),
  the record of the lab key sets kept on disk.

Until the owner commits the set, the directory holds only this README and `expected-files.txt`,
and CI checks it with `--allow-empty`.
