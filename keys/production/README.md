# Production public keys

The owner commits the production public material here, following
[docs/runbooks/production-keys.md](../../docs/runbooks/production-keys.md): the PK, KEK and db
certificates, the signed `.auth` files, the `.esl` lists, the release `cosign.pub`, the update
key's recipient `update.pub` and `fingerprints.txt`. Never a private key; a test fails the build
if one appears.
