# Releases and the update package

A release is built only from an owner-created `v*` tag on `main`, by `.github/workflows/release.yml`.
Nothing tags automatically. The same workflow has a lab dry run (`workflow_dispatch`) that builds
with keys made for that run and publishes nothing.

## What a release ships

| Output | Where | Used by |
|---|---|---|
| `sneakers-os:<version>` | GHCR, pushed by digest, with its signature | the kit, to build install media |
| `sneakers-appliance-<version>-<arch>.bin` | the GitHub Release the owner created for the tag | the box: downloaded, or uploaded by hand |
| `sneakers-product-<version>-<arch>.bin` and `sneakers-product-index.json` | built and sealed next to the base `.bin` (attaching them to the Release isn't in the workflow yet) | the box's Updates page: the product bundle, k0s and its images |

The `.bin` is the update package. The box downloads it from the GitHub Release, or an admin
uploads the identical file through :8443 or the console on an air-gapped box. Both paths read it
the same way, and the box contacts no other package source.

## The `.bin` format

```
"SNKRBIN\x01"                         magic
uint32 (big-endian) + header          JSON, below
uint32 (big-endian) + Sigstore bundle cosign sign-blob over the header bytes
age ciphertext                        the payload, to the end of the file
```

The header:

| Field | Meaning |
|---|---|
| `format`, `name` | `1`, `sneakers-appliance` |
| `version`, `arch` | the release version (SemVer, pre-release identifiers may hold hyphens, as a lab build number does: `0.0.0-lab.20261007d-g1a2b3c4`), `amd64` or `arm64` |
| `kind` | `full`, or `patch` for a hotfix |
| `bases` | a patch's exact base versions; a full version has none |
| `channel` | `production` or `lab` |
| `recipient` | the SHA-256 of the age recipient the payload is encrypted to |
| `payload` | the ciphertext's `sha256` and `size` |

The payload is the signed `sneakers-os` artifact as an OCI layout (an uncompressed tar with fixed
owners, modes and times, so the same layout gives the same bytes). The box still runs the whole
verification chain ([artifact.md](artifact.md)) on what it unpacks.

The box reads a package in this order, and refuses with the first code that applies:

1. The framing and the header parse (`UPGRADE_FORMAT`).
2. The header's signature verifies with the release key compiled into the running init
   (`UPGRADE_SIGNATURE`). A package from the other channel is `UPGRADE_CHANNEL`.
3. The signed header's channel is the box's (`UPGRADE_CHANNEL`).
4. The ciphertext's size and SHA-256 equal the header's (`UPGRADE_SIGNATURE`).
5. Only then is it decrypted with the update key read from the UKI that booted
   (`UPGRADE_DECRYPT`; see below).
6. A patch applies only on one of its exact base versions (`UPGRADE_PATCH_BASE`).

`sneakers-artifact` writes and checks packages: `bin-pack` encrypts a layout and writes the header
to sign, `bin-seal` joins the header, its bundle and the ciphertext, and `bin-verify` runs steps 1
to 4. Given `--identity` (an age key file) or `--identity-uki` (a UKI, read the way the box reads
it), it also decrypts, and with `--extract` unpacks the payload.

## The product bundle

The product stack ships as its own `.bin`, never in the base image: `sneakers-product-<version>-<arch>.bin`
(`-LAB` for a lab one), one per version and architecture. It's the same format, signed with the
same release key and encrypted to the same update key, with these header fields:

| Field | Meaning |
|---|---|
| `name` | `sneakers-product` (signed, so a base `.bin` can't pass for a product bundle or the reverse) |
| `kind` | `product` |
| `min_base` | the oldest base version it fits, SemVer, inclusive; the box refuses it on an older base (`UPGRADE_PRODUCT_BASE`, naming the range and the running base), before it decrypts anything |
| `max_base` | the newest base version it fits, inclusive; optional (no maximum when it's absent) |
| `bases` | exact base versions, for boxes that predate `min_base`; a box that reads `min_base` ignores them. A bundle sealed before the range existed carries only `bases` and is still accepted on one of them, with a note in osadmin's log. To be dropped before v0.1.0 |

The payload is the unpacked bundle as a tar: `release.yaml`, the `k0s` binary, the `helm` binary
when `release.yaml` pins one (`spec.kubernetes.helm`), `images/` (the
airgap images, each with its release-key signature, [root-image.md](root-image.md#the-airgap-bundle))
and `manifests/<stack>/*.yaml`, the stacks k0s applies (the lab bundle's hello stack and interim
edge, [k0s.md](k0s.md)), and optionally `brand/`, the product's logo and colours for the box-state
pages ([artifact.md](artifact.md#the-brand)), and optionally `product.yaml` (below). After it
decrypts and unpacks one, the box checks it like the kit checks a root: only those entries, `k0s` (and `helm`, which it carries if and only if
`release.yaml` pins it) with the SHA-256 its `release.yaml` pins, exactly the pinned images, each
signed by the release key, YAML stacks only (none named `sneakers-appliance-exposed`, the
appliance's own), a well-formed brand and a well-formed `product.yaml` (`KIT_BUNDLE_MISMATCH`,
`KIT_IMAGE_UNSIGNED`).
How it's installed and updated is in [upgrades.md](upgrades.md#the-product-bundle).

`build/product/build.sh` lays the bundle out (with `BRAND=<folder>` for a brand), runs that check (`sneakers-artifact product-check`)
and packs it for a base range (`MIN_BASE` and the optional `MAX_BASE`, `bin-pack --kind product --min-base ... --max-base ...`; `BASES`, `--base`, still adds exact bases for older boxes); the caller signs the
header and seals it with `bin-seal`. `sneakers-artifact product-index` (also `index`) writes the
index a mirror serves next to the `.bin` files: version, architecture, channel, the base range and
bases, file name and size per product bundle under `products`, and the same per base release (with
`kind`, full or patch) under `base`. Give it every `.bin` the mirror serves; the box only uses the
index to offer a choice, and verifies each `.bin` when it's staged. An index with no `base`
section (from before it existed) still reads: it offers products only. `bin-verify --extract` on a product bundle also runs the
box's check.

### product.yaml

`product.yaml` (bundle format v2, `internal/productspec`) is what a product declares to the
appliance. The appliance holds no product's names in its code; everything product-specific is here.
Today it declares the product's **exposed values**: Secret keys owners and admins may read from the
closed shell (`<product> <name>`, [ssh-and-elevation.md](ssh-and-elevation.md#product-values)) and
`ProductService` on :8443, without the root shell.

```yaml
format: 2
exposed_values:
  - name: setup-token              # the command word: "sneakers setup-token"
    secret: sneakers/sneakers-setup-token   # <namespace>/<name>
    key: SETUP_TOKEN               # the one key read
    roles: [owner, admin]          # who may read it
    one_time: true                 # never shown again once consumed_when holds
    consumed_when:                 # a GET through the API server's service proxy
      service: sneakers/sneakers-gateway:http
      path: /setup/state
      field: needsSetup
      equals: false
    label: Sneakers setup token
    link: https://{host}/admin/setup   # {host} is the box's host name
```

It's a strict allow-list. The box refuses a `product.yaml` with an unknown field, a role other than
`owner` or `admin`, a secret that isn't `<namespace>/<name>`, a name that isn't a lower-case word
(or is `mcp` or `help`), a name twice, a `one_time` value without `consumed_when`, or a link that
isn't `https://`. Once a bundle checks out, the box renders the RBAC for it into the slot
(`exposed-rbac.yaml`), which k0s applies as the stack `sneakers-appliance-exposed`: the namespace
`sneakers-appliance` with the service account `exposed-values` and, in each namespace the values
live in, a Role that may only `get` the declared Secrets by name (`resourceNames`) and the declared
signals' service proxies, never `list` or `watch`, and no ClusterRole. accessd reads as that service
account: the admin kubeconfig only mints its short token (a TokenRequest), and every read goes with
that token alone, for the declared key only. A name the bundle doesn't declare is refused for
everyone, owners included, and nothing is asked of the cluster for it. A bundle without
`product.yaml` exposes nothing.

`build/product/build.sh` takes it as `PRODUCT_YAML`; the Sneakers bundle's is
`build/product/sneakers/product.yaml`.

- **A release:** the build job packs the bundle for the release's own version and newer
  (`product-header.json`, `product-payload.age`); the sign job signs its header, seals it, opens it
  with the key in the signed UKI, checks it and writes the index.
- **A lab build:** `build/lab/build.sh` writes `product/sneakers-product-<version>-amd64-LAB.bin` and
  its index next to the disk, for the base it built and newer (`PRODUCT_MIN_BASE` and
  `PRODUCT_MAX_BASE` set another range, as a test of the refusal does), and checks it with the key in its signed UKI.

## Lab and production keys

The release key (which signs the artifact and the `.bin` header) and the update key (which the
payload is encrypted to) each have a lab and a production variant:

- **Production:** the public halves are committed in `keys/production/` (`cosign.pub`,
  `update.pub`, recorded in `fingerprints.txt`). Both private halves are secrets of the
  `production` environment (`RELEASE_COSIGN_KEY` and `UPDATE_AGE_KEY`,
  [runbooks/production-keys.md](runbooks/production-keys.md)). Encrypting needs only `update.pub`;
  the update key's private half is read only by the sign step that adds it to the UKI.
- **Lab:** `build/keys/lab-keys.sh` makes a fresh set per run, every key labelled
  `LAB ephemeral NOT FOR PRODUCTION`, on a tmpfs that's unmounted at the end of the job.

## The update key in the UKI

The box decrypts with an update key it carries in its signed UKI, as a PE section of its own,
`.updkey`:

- The sign job writes `UPDATE_AGE_KEY` to the key tmpfs, and `sneakers-artifact uki-add-key` adds
  it to the unsigned UKI. The tool refuses a key that doesn't belong to the committed
  `update.pub`, a UKI that's already signed, and a UKI that already has a key. The key file is
  removed in the same step, then the db key signs the keyed UKI, so the signature covers the key.
- On the box the key is read from the UKI systemd-boot booted (the entry `LoaderEntrySelected`
  names, found under `EFI/Linux` on the ESP) into memory only; it's never written anywhere. A UKI
  without the section is `UPGRADE_DECRYPT`.
- systemd-stub doesn't measure `.updkey`, and `internal/ukipcr` skips it too, so the key doesn't
  change PCR 11 or the box's sealing.
- The sign job checks the finished `.bin` decrypts with the key read back out of the signed UKI.
- A lab build does the same with its lab update key (`build/lab/build.sh`).

The trade-off: the encryption protects the package in transit and on download mirrors, not from
someone who holds a genuine image. Anyone with a genuine image (the published `sneakers-os`
artifact, install media or a box's ESP) can read the update key out of its UKI. A package's
authenticity comes from its signature, never from the encryption: a box installs only what the
release key signed for its channel, whoever could decrypt it.

A lab `.bin` is named `-LAB.bin`, after a version that carries its build number (`-g<short
commit>`, [testing.md](testing.md#the-lab-release)), signed with the lab key and encrypted to the lab update key, so a
production box refuses it, and the reverse. The sign job runs `check-fingerprints.sh` and refuses
any certificate or key that isn't the recorded production one.

## The workflow

| Job | Holds | Does |
|---|---|---|
| `guard` | nothing | refuses a tag that isn't `v<semver>` or whose commit isn't on `main`, and a production release before `keys/production/fingerprints.txt` and the `SNEAKERS_RELEASE_VERSION` pin (`build/release/pins.env`) exist |
| `build` | nothing | builds the kernel, the root image, the unsigned UKI and systemd-boot, the production kit, the product bundle packed for signing, and `SHA256SUMS` over all of it (`build/release/build.sh`) |
| `sign` | the `production` environment | checks `SHA256SUMS` and the fingerprints; adds the update key to the UKI; signs the UKI and systemd-boot with the db key, then the artifact, the `.bin` header and the product bundle's header with the release key; checks both `.bin` files decrypt with the key in the signed UKI, and the product bundle's contents; each key is written to a tmpfs only in the step that uses it and removed there, and the tmpfs is unmounted at the end |
| `publish` | `packages: write`, `contents: write` | verifies the artifact with the production kit and the `.bin` with the production key, pushes `sneakers-os` to GHCR, verifies what it pushed, and attaches the `.bin` and its `.sha256` to the tag's GitHub Release |
| `lab` | lab keys only | the whole path with a lab key set: builds (the lab update key in the UKI), packs, verifies, decrypts with the key in the signed UKI, unpacks, runs the lab kit on the result, opens and checks the lab product bundle, and checks a production verify of either lab `.bin` is refused; nothing leaves the run |

The release `release.yaml` and its signature come from the pinned `sneakers-release` GitHub
Release; the k0s binary from its upstream release, checked against the pin in `release.yaml`, goes
into the product bundle with the images, and so does helm's when `release.yaml` pins it. The charts and the platform add-ons join the product
bundle as their builds land; every
image in it is signed with the release key, third-party ones included. amd64 only for now; arm64
follows its kernel build.
