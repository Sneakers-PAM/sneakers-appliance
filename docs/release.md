# Releases and the update package

A release is built only from an owner-created `v*` tag on `main`, by `.github/workflows/release.yml`.
Nothing tags automatically. The same workflow has a lab dry run (`workflow_dispatch`) that builds
with keys made for that run and publishes nothing.

## What a release ships

| Output | Where | Used by |
|---|---|---|
| `sneakers-os:<version>` | GHCR (`ghcr.io/<owner>/sneakers-os`), pushed by digest, with its signature | the kit, to build install media |
| the three units: `sneakers-appliance-baseOS-<version>-g<commit>-<arch>.bin`, `sneakers-appliance-baseWeb-<version>-g<commit>-<arch>.bin` and `sneakers-product-<version>-<arch>.bin`, each with its `.inputs` | the tag's GitHub Release | the box: downloaded, or uploaded by hand on the Updates page |
| `sneakers-product-index.json` (format 2) and `SHA256SUMS` over the units | the tag's GitHub Release | a mirror, served next to the units |
| `release.yaml`, `release.yaml.sigstore.json` and one `<digest hex>.sigstore.json` per pinned image | the tag's GitHub Release | anyone checking what the release pinned: the appliance's countersignatures, made with the release key |

Each `.bin` is an update package. The box downloads it from the GitHub Release, or an admin
uploads the identical file through :8443 or the console on an air-gapped box. Both paths read it
the same way, and the box contacts no other package source.

## The three update units

From build m a box updates three units on their own, each its own signed `.bin`:

| Unit | Holds | File name (full) | Patch |
|---|---|---|---|
| Base OS | the root image, the UKI, the loader and the Secure Boot files | `sneakers-appliance-baseOS-<version>-<arch>.bin` | `sneakers-appliance-baseOS-patch-<target>-from-<base>-<arch>.bin` |
| Base Web | the :8443 admin pages, static files with a signed manifest | `sneakers-appliance-baseWeb-<version>-<arch>.bin` | none yet |
| Product | the product bundle | `sneakers-product-<version>-<arch>.bin`, unchanged | none yet |

- A lab file adds `-LAB` before `.bin`. A production Base OS or Base Web version carries the build's
  short commit once, after the version (`sneakers-appliance-baseOS-0.3.0-g1a2b3c4-amd64.bin`); a lab
  version already ends with it.
- One version line: a release stamps the units it ships with its version, and a unit it doesn't
  ship keeps its earlier version. "Tied" means the same major.minor (below).
- Base Web is one file per architecture, with the same pages in each.
- A header with no `unit` is a Base OS from before the units and keeps its old name,
  `sneakers-appliance-<version>-<arch>.bin`.

**Patches.** `sneakers-artifact patch-make --base <layout> --target <layout> --out <dir>` writes a
Base OS patch's payload (the target layout less its root image and UKI, plus `zstd -19
--long=30 --patch-from` deltas) and `patch-spec.json`, after checking that each delta rebuilds its
blob exactly with the box's own decoder. `bin-pack --unit baseOS --patch-spec <dir>/patch-spec.json`
puts the base, the target and the full file's name in the header. After the header is signed and
sealed, `patch-check --base <layout> <patch.bin>` opens it the way the box does (verify, decrypt)
and rebuilds the target from the base layout; with `--extract` the rebuilt layout is left for
`sneakers-kit verify`. A patch that doesn't rebuild is never published. How the box applies one is
in [upgrades.md](upgrades.md#base-os-patches).

**Base Web.** `sneakers-artifact web-pack --pages <built pages> --version <v> --commit <sha> --out <dir>`
lays out the payload, `pages/` and `web.yaml` (with `--requires-baseos-min` and
`--requires-baseos-before` for a range other than its own major.minor); the build signs
`web.yaml` into `web.yaml.sig` with the release key, `web-check --dir <dir>` loads it the way
:8443 does, and `bin-pack --unit baseWeb --layout <dir>` packs it, one file per architecture.

**The bridge.** A box on build l fetches only the old names and can't apply a patch or a Base Web.
The m release publishes its Base OS full file a second time under the old name (the same bytes;
the name isn't signed: `bin-seal --bridge`), and lists it in the index's legacy `base` section
(`index --bridge`). l to m is a full Base OS update; the first patch a box applies is m to m1. Later
releases don't bridge.

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
| `format`, `name` | `1`; `sneakers-appliance` (Base OS), `sneakers-appliance-web` (Base Web: a box from before the units refuses the name, so it never takes one for a root image) or `sneakers-product` |
| `unit` | `baseOS` or `baseWeb`; absent on a header from before the units (Base OS) and on a product's |
| `commit` | the short commit the file was built from; its name carries it |
| `epoch` | the signing-key generation it needs; absent reads as 1. A box takes only units of its own epoch (`UPGRADE_EPOCH`); a patch never crosses one |
| `requires` | a Base Web's `baseOS` range, `min` inclusive and `before` exclusive; absent, the same major.minor as its version (lab ranges take the lab pre-releases). A product's range stays `min_base` and `max_base` |
| `inputs` | the SHA-256 of the unit's build inputs, which the release job compares with the last published release to decide whether the unit changed (`build/lab/units.sh inputs`) |
| `version`, `arch` | the release version (SemVer, pre-release identifiers may hold hyphens, as a lab build number does: `0.0.0-lab.20261007d-g1a2b3c4`), `amd64` or `arm64` |
| `kind` | `full`, or `patch` for a Base OS delta |
| `bases` | a patch's exact base versions; a full version has none |
| `method`, `base`, `target` | a patch's method (`zstd-patch-from/1`), its base (version, root image size and SHA-256, UKI SHA-256) and its target (version, root image and UKI SHA-256, the full `.bin` to take instead) |
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
and `manifests/<stack>/*.yaml`, the stacks k0s applies, `import/job.yaml` when `product.yaml`
declares an import, (the lab bundle's hello stack and interim
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
index a mirror serves next to the `.bin` files, format 2: version, architecture, channel, the base range and
bases, file name and size per product bundle under `products`; the Base OS releases (with `kind`,
full or patch, a patch's `base_root_sha256`, and each `epoch`, `commit` and `inputs`) under `baseOS`;
the Base Web releases (with `requires`) under `baseWeb`; and a base release from before the units,
or a `--bridge` file under its old name, under `base`. Give it every `.bin` the mirror serves; the
box only uses the index to offer a choice, and verifies each `.bin` when it's staged. An index with
no `base` section (from before it existed) still reads: it offers products only. `bin-verify --extract` on a product bundle also runs the
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

It also declares the product's **components** and **switches**:

```yaml
components:                 # what every bundle of the product carries
  - {name: PostgreSQL, image: postgres}        # by the image's last path element
  - {name: sneakers-mcp, image: sneakers-mcp}
switches:                   # parts an admin turns on and off on :8443
  - name: mcp
    label: The MCP server
    default: false
    stacks: [sneakers-mcp]  # bundle stacks k0s applies only while it's on
    restart: [sneakers/deployment/sneakers-gateway]  # restarted after a change
```

The bundle check refuses a bundle whose `release.yaml` pins no image for a declared component
("the product bundle has no sneakers-mcp: no image sneakers-mcp is pinned in its release.yaml"), or that lacks a
stack a switch gates. Once a bundle checks out the box records the gated stacks in the slot
(`switch-stacks`: switch, stack, default). `k0s-interim` copies a gated stack to k0s only while its
switch is on, from the setting an admin made (`/var/lib/sneakers/platform/switches`, on the state
volume, so it outlives a reboot, an update and a revert) or else the default; the product's
progress after an apply doesn't wait for a stack that's off. The MCP page (`McpService`) drives the
switch named `mcp` (and `machine-api` when the product declares one; without it the machine API
stays on): `SetMcp` keeps the setting, puts the switch's stacks in front of k0s or takes them away
(k0s removes their objects), waits up to 90 s until k0s has applied every object in them (or
removed them all), and only then restarts the workloads it names with the installed bundle's k0s,
so a restarted workload reads the change; audited as `mcp.set`. `GetMcp` answers `state` `on`, `off`, `not in this product` or `not
installed`.

It may also declare an **import**: the product takes an export of an earlier install from the
Import page before its own first-run setup ([import.md](import.md)):

```yaml
import:
  label: Import from an earlier Sneakers
  switch: import          # a declared switch; its stack (the migrate service account) exists only while an import is open
  job: import/job.yaml    # the Job template in the bundle; the box fills ${JOB_NAME}, ${ARGS} and ${HOST_DIR}
  uid: 65532              # the Job's user, who owns the import directory
  setup: setup-token      # the one-time exposed value the product's own setup consumes
  restart: [sneakers/deployment/sneakers-vault]   # restarted after an import passes
```

The box refuses an import whose switch isn't declared, whose job isn't a `.yaml` path inside the
slot, whose uid is root, or whose setup isn't a `one_time` exposed value; the bundle check refuses a
bundle that lacks the job, or whose job still says `@MIGRATE_IMAGE@`. `build/product/build.sh`
takes the template as `IMPORT_JOB` and the pinned migrate image as `MIGRATE_IMAGE` (by digest, and
pinned in `release.yaml`), and writes `import/job.yaml` into the bundle.

`build/product/build.sh` takes it as `PRODUCT_YAML`; the Sneakers bundle's is
`build/product/sneakers/product.yaml`: every agreed component (PostgreSQL, Valkey, Kratos, Hydra,
Traefik, cert-manager and every Sneakers service, the MCP server among them), and the `mcp` switch,
off by default, which gates the `sneakers-mcp` stack. That stack holds the MCP server, Hydra and the
ConfigMap that gives the gateway and the staff web app their MCP settings, so none of it runs, and
neither app offers the MCP, until an admin turns it on. It also declares the `import` switch, off by
default, whose `sneakers-import` stack (`build/product/sneakers/import-stack.yaml`) holds the
migrate service account, and the import, with its Job template in
`build/product/sneakers/import-job.yaml`.

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
| `guard` | nothing | refuses a tag that isn't `v<semver>` or whose commit isn't on `main`, and a production release before `keys/production/fingerprints.txt` exists or while a source pin in `build/release/pins.env` is empty or isn't a full 40-character commit |
| `build` | nothing | checks out sneakers-release and sneakers-web at the pinned commits; refuses a `release.yaml` that pins an image by a placeholder, before the long build; builds the kernel, the :8443 pages, the root image (with the pages), the unsigned UKI and systemd-boot, the production kit; fetches k0s and helm (checked against `release.yaml`) and the manifest of every pinned image (checked against its digest); takes the Base OS input digest; and writes `SHA256SUMS` over all of it (`build/release/build.sh`) |
| `sign` | the `production` environment | checks `SHA256SUMS` and the fingerprints; adds the update key to the UKI; signs the UKI and systemd-boot with the db key; countersigns `release.yaml` and every pinned image's manifest with the release key; assembles and signs the artifact; builds the product bundle from the countersigned images; seals the three units with `build/lab/units.sh` on the production channel; opens each the way the box does (the production kit checks the Base OS); each key is written to a tmpfs only in the step that uses it and removed there, and the tmpfs is unmounted at the end |
| `publish` | `packages: write`, `contents: write` | verifies the artifact with the production kit, each unit with the production key and every countersignature with `cosign verify-blob`, pushes `sneakers-os` to GHCR, verifies what it pushed, and attaches the units, their `.inputs`, the index, `SHA256SUMS`, `release.yaml` and the countersignatures to the tag's GitHub Release (a draft when the owner made none; nothing publishes it) |
| `lab` | the `lab` environment, lab keys only | the whole path with a lab key set: builds (the lab update key in the UKI), packs, verifies, decrypts with the key in the signed UKI, unpacks, runs the lab kit on the result, opens and checks the lab product bundle, and checks a production verify of either lab `.bin` is refused; nothing leaves the run |

## The environments

Each job that can touch a key names its environment; no other job names one, and no key is ever a
repository or organization secret.

| Environment | Used by | Protection | Secrets |
|---|---|---|---|
| `production` | the `sign` job of a `v*` tag run | required reviewer Bugs5382; deployments from `v*` tags only (a custom tag policy); no admin bypass | `SB_DB_KEY`, `RELEASE_COSIGN_KEY`, `RELEASE_COSIGN_PASSWORD`, `UPDATE_AGE_KEY` |
| `lab` | the `lab` job (the lab dry run, by hand) | none | none: the job makes a fresh lab key set for each run |

- The owner sets the four production values from the production keys runbook
  ([runbooks/production-keys.md](runbooks/production-keys.md)); nothing in CI writes, reads back or
  copies them. The PK and KEK private keys are never GitHub secrets.
- Self-review stays allowed on `production`: the owner both pushes the tag and approves the
  deployment, and is its only reviewer, so blocking self-review would leave a release no one can
  approve. Admins can't bypass the review.
- A lab secret, if a lab job ever needs one, goes into `lab`, never `production` and never the
  repository.

The settings applied are in `build/ci/environment-production.json` and
`build/ci/environment-lab.json`:

```bash
gh api -X PUT repos/Sneakers-PAM/sneakers-appliance/environments/production --input build/ci/environment-production.json
gh api -X POST repos/Sneakers-PAM/sneakers-appliance/environments/production/deployment-branch-policies -f name='v*' -f type=tag
gh api -X PUT repos/Sneakers-PAM/sneakers-appliance/environments/lab --input build/ci/environment-lab.json
```

## The pinned sources

`build/release/pins.env` pins what a production release is built from, each as a repository and a
full commit: `SNEAKERS_RELEASE_REPO` and `SNEAKERS_RELEASE_COMMIT` (its `manifest/release.yaml`),
`SNEAKERS_WEB_REPO` and `SNEAKERS_WEB_COMMIT` (`apps/appliance-admin`, the :8443 pages). They're git
content, not release assets, so neither repository has to tag before the appliance does. The
appliance signs what it takes: the sign job countersigns `release.yaml` and the manifest of every
image it pins with the release key, and those signatures are the ones the kit, the bundle check
and the box verify. Bump a pin by hand, in a PR of its own, to a commit on that repository's
`main`; a `release.yaml` with a placeholder digest (`sha256:TBD-at-release`) is refused by the build
job before the long build.

The k0s binary comes from its upstream release, checked against the pin in `release.yaml`, and goes
into the product bundle with the images, and so does helm's when `release.yaml` pins it. The first
production release ships full units only: no bridge copy and no patch (`build/lab/units.sh` refuses
`BRIDGE=1` on the production channel). Choosing only the units whose inputs changed since the last
release isn't in the workflow yet: every release builds all three. The charts and the platform add-ons join the product
bundle as their builds land; every
image in it is signed with the release key, third-party ones included. amd64 only for now; arm64
follows its kernel build.
