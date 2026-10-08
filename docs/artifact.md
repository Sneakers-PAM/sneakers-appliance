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
- **The UKI** carries the channel's update key as its `.updkey` section, added before it's signed
  ([release.md](release.md)).
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

## Verification

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
6. **Authenticode (amd64):** the UKI and systemd-boot verify against the pinned db certificate, so a
   file the firmware would refuse is caught before an image is built (`KIT_AUTHENTICODE`). On
   arm64 this step instead requires the boot tarball to hold exactly the files `appliance.yaml`
   lists under `boot.arm64.files`, each with its SHA-256 (`KIT_DIGEST_MISMATCH`).
7. **Root integrity:** `sneakers.roothash` and `sneakers.hashoffset` are read from the signed
   command line (the UKI's `.cmdline` section on amd64, `cmdline.txt` in the boot tarball on
   arm64) and must equal `spec.root.verity`. The dm-verity tree is recomputed in Go over the whole
   root image; the stored tree must match it byte for byte and give that root hash
   (`KIT_VERITY_MISMATCH`). The tree format is `veritysetup format`'s default: format 1, SHA-256,
   4096-byte blocks, the superblock at the hash offset, then the levels, top first.
8. **Base root:** the root is opened read-only as SquashFS.
   `/usr/share/sneakers/release/release.yaml` must be the verified `release.yaml`, and the root
   must carry no `/usr/bin/k0s` and no images in `/usr/share/sneakers/images/`
   (`KIT_BUNDLE_MISMATCH`): k0s and the images ship in the product bundle, which the box checks
   the same way when it unpacks one (k0s's SHA-256 and exactly the pinned images, each signed by
   the release key, `KIT_BUNDLE_MISMATCH` or `KIT_IMAGE_UNSIGNED`;
   [release.md](release.md#the-product-bundle)).
9. **Enrolment material (amd64):** `keys/PK.esl`, `KEK.esl` and `db.esl` each hold exactly the
   pinned certificate; `PK.auth` and `KEK.auth` verify against PK and `db.auth` against KEK, each
   carrying its `.esl`; `dbx.esl` is a valid (at v0.1.0, empty) signature list
   (`KIT_WRONG_SIGNER`). The signature check covers the variable name, vendor GUID, attributes,
   timestamp and data, as the firmware's does, and trusts only the pinned certificate, whatever
   the file embeds.

## The airgap images

The product bundle's `images/` holds one OCI image archive per pinned image, named
`<sha256 hex of the pinned digest>.tar`, whose `index.json` lists that digest, and beside it
`<hex>.tar.sigstore.json`, the release-key signature of that digest. Nothing else may be in the
directory. The images pinned are those under `spec.services`, `spec.thirdParty`, `spec.platform`
and `spec.kubernetes.k0s.images` of `release.yaml`; `spec.tools` (the helm test pod) isn't
bundled. A placeholder digest (`sha256:TBD-at-release`) is refused.

## Lab keys

`build/keys/lab-keys.sh <outdir>` makes a throwaway key set for one CI run: PK, KEK, db and a
rogue db (RSA-2048, subject `Sneakers-PAM LAB ephemeral NOT FOR PRODUCTION <role>`), their EFI
signature lists and signed `.auth` files, and the cosign and rogue cosign key pairs. It writes only
into the directory it's given, and nothing it makes is stored, published or uploaded. It needs
`openssl`, `efitools` and `cosign`; `build/ci/install-cosign.sh` installs the pinned cosign.

The unit tests build their fixture artifacts in Go with keys made once per test binary
(`test/kit/fixtures`): stub UKIs and loaders signed with Authenticode, a SquashFS root with its
verity tree and a signed bundle, and signed `.auth` files. Only the verity cross-check needs a tool
(`veritysetup`, installed in CI). The `🔑 Lab keys and tool interop` CI job runs the script with the
real tools and checks each against the kit: cosign's bundles, efitools' `.auth` and `.esl` files and
sbsign's signatures verify with the kit's checks, and `sbverify` and `unsquashfs` accept what the
fixtures write.
