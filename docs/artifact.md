# The sneakers-os artifact

What the org publishes on a tag, and what `sneakers-kit` and the box's `Image.Stage` verify. It
holds signed build inputs, never bootable media.

## Shape

An OCI image index, pushed by digest (`ghcr.io/sneakers-pam/sneakers-os:<version>` is a
convenience tag) or kept as an OCI image layout directory for offline sites.

- **The index** lists one image manifest per architecture, each with `platform` `linux/amd64` or
  `linux/arm64`.
- **Each manifest** has `artifactType` `application/vnd.sneakers-pam.os.v1`, the empty config, and
  one layer per release file. A layer's file name is its `org.opencontainers.image.title`
  annotation:

  | File | Media type | amd64 | arm64 |
  |---|---|---|---|
  | `appliance.yaml` | `application/vnd.sneakers-pam.appliance.v1+yaml` | yes | yes |
  | `release.yaml`, `release.yaml.sigstore.json` | `application/vnd.sneakers-pam.file.v1` | yes | yes |
  | `root-<version>.img` | `application/vnd.sneakers-pam.file.v1` | yes | yes |
  | `sneakers-<version>.efi`, `systemd-bootx64.efi` | `application/vnd.sneakers-pam.file.v1` | yes | no |
  | `keys/{PK,KEK,db}.auth`, `keys/{PK,KEK,db,dbx}.esl` | `application/vnd.sneakers-pam.file.v1` | yes | no |
  | `boot-arm64-<version>.tar` | `application/vnd.sneakers-pam.file.v1` | no | yes |

- **The signature** is a Sigstore bundle (v0.3) attached to the index as an OCI referrer: an image
  manifest whose `subject` is the index, with `artifactType`
  `application/vnd.dev.sigstore.bundle.v0.3+json` and the bundle as its one layer. It signs the
  index digest, so it covers every manifest and file through their digests.
- **`release.yaml.sigstore.json`** is the bundle `cosign sign-blob --key --bundle` writes for
  `release.yaml`.

In a layout directory, `index.json` lists exactly one image index: the artifact. The signature
referrer may be listed too; the kit finds it either way.

## Signatures

Both signatures are made with the org release key (cosign, ECDSA P-256) and verified against the
public key compiled into the kit and into the box's init. There is no keyless path and no
transparency-log dependency, so an offline site verifies the same way. A bundle may carry
transparency-log entries; they're logged, not trusted.

A bundle with a message signature must name the artifact's SHA-256 and verify over it. A bundle
with a DSSE envelope must verify over the envelope's pre-authentication encoding and carry an
in-toto statement with the artifact's digest as a subject.

## Verification, steps 1 to 5

The first failure stops the run with its code and writes nothing.

1. **Resolve:** the reference becomes one digest, logged. The index and the architecture's
   manifest are read and checked against their digests (`KIT_DIGEST_MISMATCH`), and every layer
   must have a unique title.
2. **Artifact signature:** a bundle referrer of the index verifies with the pinned release key.
   None: `KIT_SIG_MISSING`; signed with another key: `KIT_WRONG_SIGNER`.
3. **Appliance manifest:** see [kit.md](kit.md).
4. **Release manifest:** `release.yaml.sigstore.json` verifies `release.yaml` with the same key
   (`KIT_SIG_MISSING`, `KIT_WRONG_SIGNER`), and `release.yaml`'s digest is `spec.release.digest`
   (`KIT_DIGEST_MISMATCH`).
5. **File digests:** the artifact carries exactly the files `appliance.yaml` lists, and each one's
   SHA-256 is the one listed (`KIT_DIGEST_MISMATCH`).

## Lab keys

`build/keys/lab-keys.sh <outdir>` makes a throwaway key set for one CI run: PK, KEK, db and a
rogue db (RSA-2048, subject `Sneakers-PAM LAB ephemeral NOT FOR PRODUCTION <role>`), their EFI
signature lists and signed `.auth` files, and the cosign and rogue cosign key pairs. It writes only
into the directory it's given, and nothing it makes is stored, published or uploaded. It needs
`openssl`, `efitools` and `cosign`; `build/ci/install-cosign.sh` installs the pinned cosign.

The unit tests build their fixture artifacts in Go with keys made once per test binary
(`test/kit/fixtures`), so they need no tools. The `🔑 Lab keys and cosign` CI job runs the script
with the real tools and checks that a bundle written by cosign verifies with the kit's verifier.
