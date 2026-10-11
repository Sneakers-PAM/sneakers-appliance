# Releases and the update package

A release is built only from an owner-created `v*` tag on `main`, by `.github/workflows/release.yml`.
Nothing tags automatically. The same workflow has a lab dry run (`workflow_dispatch`) that builds
with keys made for that run and publishes nothing.

## What a release ships

| Output | Where | Used by |
|---|---|---|
| `sneakers-os:<version>` | GHCR (`ghcr.io/<owner>/sneakers-os`), pushed by digest, with its signature | the kit, to build install media |
| `sneakers-appliance-<version>-amd64.ova`, with `.sha256`, its line in `SHA256SUMS` and `.sigstore.json` (a signature by the release key) | the tag's GitHub Release | a new install on VMware: the production kit writes it in the sign job from the signed artifact (it verifies the artifact first), with the vApp host name and domain properties ([kit.md](kit.md)); check it with `sha256sum -c` and `cosign verify-blob --key keys/production/cosign.pub --bundle <ova>.sigstore.json --insecure-ignore-tlog=true <ova>` |
| the three units: `sneakers-appliance-baseOS-<version>-<arch>.bin`, `sneakers-appliance-baseWeb-<version>-<arch>.bin` and `sneakers-product-<version>-<arch>.bin`, each with its `.inputs` | the tag's GitHub Release | the box: downloaded, or uploaded by hand on the Updates page |
| a Base OS patch from the previous release on the tag's channel, `sneakers-appliance-baseOS-patch-<previous>-to-<version>-<arch>.bin`, with its `.inputs` (none for the first release on a channel) | the tag's GitHub Release | a box on the previous release: a small download in place of the full Base OS |
| `sneakers-product-index.json` (format 2) and `SHA256SUMS` over the units and the OVA, each with its signature by the release key (`sneakers-product-index.json.sigstore.json`, `SHA256SUMS.sigstore.json`) | the tag's GitHub Release | the box's GitHub source, which takes the index only when its signature verifies ([upgrades.md](upgrades.md#the-github-source)); a mirror, served next to the units |
| `release.yaml`, `release.yaml.sigstore.json` and one `<digest hex>.sigstore.json` per pinned image | the tag's GitHub Release | anyone checking what the release pinned: the appliance's countersignatures, made with the release key |

The GitHub Releases are the boxes' built-in update source: an rc tag (`v<x.y.z>-rc.<n>`) is made a
prerelease, which boxes on the rc channel take and boxes on stable never do, and every asset must
be under GitHub's 2 GiB limit (`build/release/check-asset-sizes.sh` refuses the publish otherwise,
and the lab dry run checks its files, its lab OVA among them, the same way). Every file has one of
the names below (`build/release/check-names.sh`, run by the sign, publish and lab jobs and by
`build/lab/units.sh`).

## File names

A file name carries the release and nothing else: the version on production (`0.1.0-rc.1`, and
`0.1.0` for the stable release), and `lab-<build label>` on lab, where the label is the build's
letter and rebuild number (`lab-n3`), with `w<n>` for a Base Web-only hotfix on that build (`lab-n5w1`), or the product's own lab label (`lab-sneakers.10`). The build
date, the build time and the commit are never in a name; they stay in the signed header and the
index (`version`, `commit`), where the box and the :8443 pages read them. `<arch>` is `amd64` or
`arm64`; in the table, `<v>` stands for the version or `lab-<label>`.

| File | Production example | Lab example | State |
|---|---|---|---|
| Base OS `sneakers-appliance-baseOS-<v>-<arch>.bin` | `sneakers-appliance-baseOS-0.1.0-rc.1-amd64.bin` | `sneakers-appliance-baseOS-lab-n3-amd64.bin` | produced |
| Base Web `sneakers-appliance-baseWeb-<v>-<arch>.bin` | `sneakers-appliance-baseWeb-0.1.0-rc.1-amd64.bin` | `sneakers-appliance-baseWeb-lab-n3-amd64.bin` | produced |
| Base OS patch `sneakers-appliance-baseOS-patch-<from>-to-<to>-<arch>.bin` | `sneakers-appliance-baseOS-patch-0.1.0-rc.1-to-0.1.0-rc.2-amd64.bin` | `sneakers-appliance-baseOS-patch-lab-n2-to-n3-amd64.bin` | produced |
| Product `sneakers-product-<v>-<arch>.bin` | `sneakers-product-0.1.0-rc.1-amd64.bin` | `sneakers-product-lab-sneakers.10-amd64.bin` | produced |
| ESXi/vSphere `sneakers-appliance-<v>-amd64.ova` | `sneakers-appliance-0.1.0-rc.1-amd64.ova` | `sneakers-appliance-lab-n3-amd64.ova` | produced |
| Proxmox/KVM `sneakers-appliance-<v>-amd64.qcow2` | `sneakers-appliance-0.1.0-amd64.qcow2` | `sneakers-appliance-lab-n3-amd64.qcow2` | reserved: the kit can write it (`--format qcow2`), but no release builds or publishes it until Proxmox support is built and proven |
| ISO installer `sneakers-appliance-<v>-amd64.iso` | `sneakers-appliance-0.1.0-amd64.iso` | `sneakers-appliance-lab-n3-amd64.iso` | reserved: no ISO writer yet |
| Raspberry Pi SD image `sneakers-appliance-<v>-arm64.img.xz` | `sneakers-appliance-0.1.0-arm64.img.xz` | `sneakers-appliance-lab-n3-arm64.img.xz` | reserved: no arm64 build yet |
| Installed disk `sneakers-appliance-<v>-<arch>.raw` | none | `sneakers-appliance-lab-n3-amd64.raw` | lab build output only, never published |

- **Sidecars** follow their file's name: `<file>.inputs` (a unit's input digest), `<file>.sha256`,
  `<file>.sigstore.json` (a cosign signature bundle by the release key) and `<file>.sig`.
- **Fixed names:** `sneakers-product-index.json`, `SHA256SUMS`, `release.yaml` (each with its
  `.sigstore.json`) and one `<digest hex>.sigstore.json` per pinned image.
- **Every produced image** gets its `.sha256`, a line in `SHA256SUMS` and its `.sigstore.json`. The
  index lists only the update units; no image is in it, since a box never installs one.
- **The check:** `build/release/check-names.sh --channel production|lab <file>...` takes these
  shapes only, so an unknown name fails too, and refuses a name with a date (8 digits), a build
  time (`r` and 14 digits) or a commit (`-g<hex>`), and a lab name on production or the reverse.
- **Names from earlier builds:** the box finds every file through the index, never by working out
  a name, so it reads an index that lists files under the names earlier builds used
  (`-LAB` before `.bin`, the commit and the build date in the version,
  `...-patch-<to>-from-<from>-...`; `updatepkg.PreviousFileName`). On lab, `build/lab/units.sh`
  also links each unit under that earlier name and lists it in the index (`OLD_NAMES=1`, the lab
  default), so a box still running one of those builds finds its update. With `OLD_NAMES=1` each
  patch also names its full release by the earlier name (`sneakers-artifact bin-pack
  --previous-full-name`, lab only): a box from before the version-only names checks that name and
  refuses the new one. A patch's fallback to the full release takes the name the last checked
  index lists for it.

Each `.bin` is an update package. The box downloads it from the GitHub Release, or an admin
uploads the identical file through :8443 or the console on an air-gapped box. Both paths read it
the same way, and the box contacts no other package source.

## The three update units

From build m a box updates three units on their own, each its own signed `.bin`:

| Unit | Holds | File name (full) | Patch |
|---|---|---|---|
| Base OS | the root image, the UKI, the loader and the Secure Boot files | `sneakers-appliance-baseOS-<v>-<arch>.bin` | `sneakers-appliance-baseOS-patch-<base>-to-<target>-<arch>.bin` |
| Base Web | the :8443 admin pages, static files with a signed manifest | `sneakers-appliance-baseWeb-<v>-<arch>.bin` | none yet |
| Product | the product bundle | `sneakers-product-<v>-<arch>.bin` | none yet |

- `<v>` is the version on production and `lab-<build label>` on lab ([File names](#file-names)); the
  commit and the build time are in the header, not the name.
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
Every Base OS release ships with one: `build/lab/units.sh` refuses a build without the pages, seals
the Base Web first, and passes `bin-pack --includes-baseweb <version>` for the Base OS and each patch.

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
| `requires` | a Base Web's `baseOS` range, `min` inclusive and `before` exclusive; absent, the same major.minor as its version (lab ranges, and a pre-release's such as an rc's, take pre-releases at both ends, so Base Web `0.2.0-rc.2` fits Base OS `0.2.0-rc.1`). A product's range stays `min_base` and `max_base` |
| `includes` | a Base OS release's `baseWeb`: the version of the Base Web it ships with (the same version, from the same pages). `build/lab/units.sh` always seals the Base Web first and names it on the Base OS and its patches; the release job checks the pair. Absent on releases from before the rule |
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

The product stack ships as its own `.bin`, never in the base image: `sneakers-product-<v>-<arch>.bin`
(`sneakers-product-lab-<label>-<arch>.bin` for a lab one, [File names](#file-names)), one per version and architecture. It's the same format, signed with the
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
and `manifests/<stack>/*.yaml`, the stacks k0s applies (the Sneakers stacks below, the interim edge
and, in the lab bundle, the hello stack, [k0s.md](k0s.md)), `import/job.yaml` when `product.yaml`
declares an import, and optionally `brand/`, the product's logo and colours for the box-state
pages ([artifact.md](artifact.md#the-brand)), and optionally `product.yaml` (below). After it
decrypts and unpacks one, the box checks it like the kit checks a root: only those entries, `k0s` (and `helm`, which it carries if and only if
`release.yaml` pins it) with the SHA-256 its `release.yaml` pins, exactly the pinned images, each
signed by the release key, YAML stacks only (none named `sneakers-appliance-exposed` or
`sneakers-appliance-secrets`, the appliance's own), a well-formed brand and a well-formed `product.yaml` (`KIT_BUNDLE_MISMATCH`,
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

### The Sneakers stacks

`build/product/sneakers/render.sh` renders the Sneakers stacks the same way for every channel: two
`helm template` runs of sneakers-release's `charts/sneakers` (its own `scripts/build-deps.sh`
resolves the dependencies), over `charts/sneakers/examples/values-small-box.yaml` with
`build/product/sneakers/values.yaml`, the MCP switch off and then on
(`values-mcp-on.yaml`). `build/tools/stack` turns them into the stacks:

| Stack | Holds |
|---|---|
| `sneakers` | always on: the `sneakers` namespace and everything of the product that isn't a workload (Services, ConfigMaps, NetworkPolicies, RBAC, Ingresses) |
| `sneakers-data` | the data phase: PostgreSQL and Valkey |
| `sneakers-identity` | the identity phase: Kratos, the identity service and the vault |
| `sneakers-services` | the services phase: workflow, audit, notify, connector and the SSH broker |
| `sneakers-front` | the front phase: the gateway and the two web apps |
| `sneakers-mcp` | what only the on render has (the MCP server and Hydra), and the `sneakers-mcp-switch` ConfigMap with the gateway and staff web settings the switch changes, which both load (`envFromConfigMaps`, optional); placed with the front phase, before its own stack, while the MCP switch is on |
| `sneakers-import` | the migrate service account (`build/product/sneakers/import-stack.yaml`), applied while an import is open ([import.md](import.md)) |
| `edge` | the interim edge on 443 (`build/lab/stacks/edge`) |

Each workload goes in its phase's own stack (`product.yaml` `phases`, below), labelled
`sneakers-appliance/phase` and `sneakers-appliance/phase-order` on itself and its pods, and the
tool refuses a workload no phase names, or a switch's workload whose phase doesn't place the
switch's stack. The bundle check refuses a bundle without a phase's stack, with a workload in
it that its phase doesn't name or that lacks the labels, or with a switch's stack that runs a
workload and that no phase places (`switch_stacks`).

The renders layer sneakers-release's `migrate/deploy/migrate-callers-values.yaml`, so the vault
and audit list the migrate caller and the NetworkPolicies admit it; the import's
Job template goes into the bundle as `import/job.yaml` with the sneakers-migrate image the release
built (`spec.jobs.migrate`). On the way every container gets the image `release.yaml` pins, by digest, and is never pulled; a
volume claim becomes a hostPath under `/var/lib/sneakers-data`, owned by the pod's user; an Ingress
loses its host and TLS (the edge serves every name on 443 with the box's certificate). No secret
value is carried: the chart's bundled Secrets are dropped, and the tool refuses a render with a
Secret, or a workload reading a Secret key, that `product.yaml` doesn't declare as a box secret.
The production values log at `error` in JSON. `render_test.sh` renders sneakers-release at the
pinned commit and checks that every component is pinned, every service image runs in a stack,
every image is pinned by digest, no stack carries a Secret, and nothing of a lab build is left (no
lab registry or name, no debug or console logging, no dev-only switch). A lab build may layer its
own values on top (`EXTRA_VALUES`).

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
so a restarted workload reads the change. Then it waits, up to 90 s (inside the 2 minutes :8443 and
the closed shell wait), until the product is ready with the change, as an apply's progress counts it:
every workload in the stacks that are on has rolled out, with the restarted ones, and the product's
health answers. It answers ok only then; a stack, a restart or a product that isn't ready in time
fails the call (`PRODUCT_NOT_READY`, with what it still waits for), and the setting stays saved.
Audited as `mcp.set`, with that outcome. `GetMcp` answers `state` `on`, `off`, `not in this product`
or `not installed` (the setting) and, while it's on, `readiness`: `starting` with `detail` (what the
product waits for), `ready`, or `failed` with `detail` (why the last switch-on gave up, until the
product is ready).

It may declare when it's **ready** after an install, an update or a revert
([upgrades.md](upgrades.md#when-the-product-is-ready)):

```yaml
ready:
  health:                   # a GET through the API server's service proxy; 2xx is ready
    service: sneakers/sneakers-gateway:http
    path: /readyz
  timeout: 15m              # from 1m to 2h; without it the box waits 10 minutes
```

The box refuses a health check whose service isn't `<namespace>/<service>:<port>` or whose path
isn't a plain absolute path, and a timeout outside 1m to 2h. Without `ready` the box still waits for
every workload in the stacks to roll out and for 443, with its own 10 minutes.

It may declare its **phases**, the order it comes up in on every boot, update and revert, each
Ready before the next ([upgrades.md](upgrades.md#the-phases)):

```yaml
phases:
  - name: data                      # a lower-case word; the step is phase:data
    label: Starting the database and the cache
    stack: sneakers-data            # the phase's own stack; the render puts its workloads in it
    workloads: [sneakers-postgres, sneakers-valkey]
    timeout: 5m                     # from 1m to 1h; 5 minutes without it
  - name: front
    label: Starting the gateway and the web apps
    stack: sneakers-front
    workloads: [sneakers-gateway, sneakers-web-staff, sneakers-web-admin, sneakers-mcp, sneakers-hydra]
    switch_stacks: [sneakers-mcp]   # switch-gated stacks placed with the phase, before its own
    needs:                          # per workload, the Services of earlier phases it connects to
      sneakers-hydra: [sneakers-postgres:5432]
```

The render gives each phased workload a first init container, `wait-phase`, that runs the
release's sneakers-migrate image (`spec.jobs.migrate`, `build/tools/stack --wait-job migrate`):
`sneakers-migrate wait --dns kubernetes.default.svc.cluster.local --tcp <service>.<namespace>.svc:<port> ... --every 2s`
resolves the cluster's DNS, then connects to each of the workload's needs in turn, retrying every
2 seconds. A Service with no Ready endpoint refuses the connection, so the wait follows each
dependency's own readiness, and the workload's NetworkPolicies already admit it. It has no timeout
of its own: the phase's timeout bounds it. A need that isn't `<service>:<port number>`, or that
names a workload of another phase, is refused.

The box refuses a phase whose name isn't a lower-case word or comes twice, one without a label or
workloads, a stack that another phase, a switch or the appliance has, a workload two phases name,
a switch stack no switch gates (or the import's), and a timeout outside 1m to 1h. A slot records
its phase stacks in `phase-stacks` for k0s-interim, which leaves them to the phase loop. Without
`phases` the product comes up as before: every stack at once.

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
  after: services         # with phases: the phase the product holds after while an import is open
```

The box refuses an import whose switch isn't declared, whose job isn't a `.yaml` path inside the
slot, whose uid is root, or whose setup isn't a `one_time` exposed value; the bundle check refuses a
bundle that lacks the job, or whose job still says `@MIGRATE_IMAGE@`. `build/product/build.sh`
takes the template as `IMPORT_JOB` and the pinned migrate image as `MIGRATE_IMAGE` (by digest, and
pinned in `release.yaml`), and writes `import/job.yaml` into the bundle.

It may also name the product's **escrow** keys, the Secret keys its data can't be opened without,
which the box keeps in the recovery escrow ([key-custody.md](key-custody.md#product-keys)):

```yaml
escrow:
  - name: vault-root-key            # sealed as product-<product>-vault-root-key
    secret: sneakers/sneakers-box
    key: VAULT_ROOT_KEK
```

The appliance's Role may `get` those Secrets too. The box refuses a name that isn't a lower-case
word or is named twice, a secret that isn't `<namespace>/<name>` and a key that isn't a Secret data
key.

It also declares the **box values** its stacks read, each by a placeholder under the reserved
`.invalid` domain, which never resolves:

```yaml
box_values:
  - value: box.fqdn                       # the box's FQDN
    placeholder: sneakers.box.invalid     # what the stacks carry where the host goes; scrub:allow=fqdn
  - value: box.os.version                 # the Base OS version the box runs
    placeholder: baseos-version.invalid   # scrub:allow=fqdn
  - value: box.web.version                # the Base Web version the box serves
    placeholder: baseweb-version.invalid  # scrub:allow=fqdn
```

The box offers three values:

- **`box.fqdn`:** the box's FQDN ([network.md](network.md#the-host-name)), recorded at each product
  apply and revert and when the host name changes.
- **`box.os.version`:** the running Base OS's version, recorded by init at every boot, before any
  service starts (so the k0s start after a Base OS update takes the new one), and at each product
  apply and revert.
- **`box.web.version`:** the Base Web version the box serves, recorded at the same times. It is the
  slot osadmin last served, or the Base OS's own version for the built-in pages, so a Base Web
  update reaches the product at the next boot or product apply.

The box refuses a value it doesn't offer, one declared twice, a placeholder that isn't a lower-case
name under `.invalid`, or one that holds another's (each is replaced as plain text). It records them
in the slot (`box-values`: placeholder, value), and puts its own value in place of each placeholder
when a stack goes in front of k0s; a value it hasn't recorded leaves its placeholder. The Sneakers
bundle's values set `global.host` to the FQDN placeholder, so every host-dependent setting carries it
and no bundle names a box, and give the gateway all three (`SNEAKERS_APPLIANCE_FQDN`,
`SNEAKERS_APPLIANCE_VERSION`, `SNEAKERS_APPLIANCE_WEB_VERSION`) for the product's About and
diagnostics. `render.sh` also gives it the release's own version (`metadata.version`, read with
`bundle version`) as `SNEAKERS_PRODUCT_VERSION`.

And it declares the **box secrets**, the Secrets every box makes for itself, so no bundle carries a
secret value and no two boxes share one:

```yaml
box_secrets:
  - secret: sneakers/sneakers-bundled         # <namespace>/<name>
    keys:
      - {key: password, generate: password}   # 32 letters and digits
      - {key: redis-url, value: "redis://:{valkey-password}@sneakers-valkey:6379/0"}
      - {key: valkey-password, generate: password}
  - secret: sneakers/sneakers-box
    keys:
      - {key: VAULT_ROOT_KEK, generate: key32}  # 32 random bytes, base64
  - secret: sneakers/sneakers-setup-token
    keys:
      - {key: SETUP_TOKEN, generate: token}     # 32 random bytes, URL-safe base64
```

A key is either generated (`password`, `key32` or `token`) or a `value`, which may name generated
keys as `{key}` (the same Secret's) or `{secret/key}` (another box secret's in the same namespace).
The box refuses a key that's both or neither, an unknown generator, a key or a Secret twice, a
reference to a key that isn't generated, a brace that isn't closed, and the appliance's own
namespace. At each product apply and revert, after the slots switch and before k0s restarts,
accessd makes every generated value the current slot declares that it hasn't made before (from the
kernel's random source; a key `escrow` names is first read from the box's sealed item
`product-<product>-<name>`, which a replacement box has from its imported escrow, see
[key-custody.md](key-custody.md#product-keys)) and keeps them in `/var/lib/sneakers/platform/box-secrets.json` (mode
0600, on the encrypted state volume). It then writes the Secrets that slot declares as the stack
`sneakers-appliance-secrets` (`/var/lib/k0s/manifests`, mode 0600). A value is never made twice:
updates, reverts and reboots keep it, and a value a later bundle stops declaring is kept for one
that declares it again. A bundle that declares none leaves no stack. No value is logged. If they
can't be made, the apply stops before k0s is touched. The keys `escrow` names (the Sneakers bundle's vault
root key and TOTP key, in `sneakers-box`) also go into the recovery escrow. INTERIM: platformd seals
all of them through KeyCustody when it lands (#100).

A box secret key may also be a `setting` (`{key: SMTP_PASS, setting: email.password}`): one of
the settings an admin sets on :8443. The product declares the non-secret ones as **box
settings**, ConfigMaps the box writes into the same stack (`box_settings`), and says it reads the
box's email settings with an `email` section, which also names the workloads restarted after a
change. A secret setting in a ConfigMap, an unknown setting, a key that's more than one of
generated, value and setting, and settings with no `email` section are refused. See
[product-email.md](product-email.md).

And it may declare its **data paths**, which the box's disk guard samples for growth
([disk-layout.md](disk-layout.md#alerts-and-warnings)):

```yaml
data:
  - name: database             # a lower-case word
    label: The database        # what Status shows
    path: postgres             # under /var/lib/sneakers-data, where the stacks' volumes are
    wal: pgdata/pg_wal         # optional: the write-ahead log, under path
    wal_warn: 1GiB             # with wal: the size Status warns past (KiB, MiB, GiB or TiB)
```

The box refuses a name that isn't a word or is declared twice, a missing label, a path that is
absolute, unclean or leaves the data root, a `wal` that leaves its path, and a `wal` without a
`wal_warn` or the other way round. The box never removes a WAL file: the product keeps its own
within its settings. With no `data`, the guard samples every directory under the data root. The
section is new in this release: an appliance older than it refuses a `product.yaml` that has one,
so the base goes first.

`build/product/build.sh` takes it as `PRODUCT_YAML`; the Sneakers bundle's is
`build/product/sneakers/product.yaml`: every agreed component (PostgreSQL, Valkey, Kratos, Hydra,
Traefik, cert-manager and every Sneakers service, the MCP server among them), and the `mcp` switch,
off by default, which gates the `sneakers-mcp` stack. That stack holds the MCP server, Hydra and the
ConfigMap that gives the gateway and the staff web app their MCP settings, so none of it runs, and
neither app offers the MCP, until an admin turns it on. It also declares the `import` switch, off by
default, whose `sneakers-import` stack (`build/product/sneakers/import-stack.yaml`) holds the
migrate service account, and the import, with its Job template in
`build/product/sneakers/import-job.yaml`. Its box secrets are every Secret the
Sneakers stacks read: the bundled PostgreSQL, Valkey, Kratos and Hydra credentials, the vault root
key and TOTP key (`sneakers-box`) and the setup token it exposes. Its data path is the database's
(`postgres`, its WAL warned past 1 GiB), and its values hold PostgreSQL's WAL to `max_wal_size`
512MB.

- **A release:** the build job packs the bundle for the release's own version and newer
  (`product-header.json`, `product-payload.age`); the sign job signs its header, seals it, opens it
  with the key in the signed UKI, checks it and writes the index.
- **A lab build:** `build/lab/build.sh` writes `product/sneakers-product-lab-<label>-amd64.bin` and
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

A lab `.bin` is named `...-lab-<label>-<arch>.bin` ([File names](#file-names)); its version carries
the build number (`-g<short commit>`, [testing.md](testing.md#the-lab-release)) in the header. It's signed with the lab key and encrypted to the lab update key, so a
production box refuses it, and the reverse. The sign job runs `check-fingerprints.sh` and refuses
any certificate or key that isn't the recorded production one.

## The workflow

| Job | Holds | Does |
|---|---|---|
| `guard` | nothing | refuses a tag that isn't `v<semver>` or whose commit isn't on `main`, and a production release before `keys/production/fingerprints.txt` exists or while a source pin in `build/release/pins.env` is empty or isn't a full 40-character commit |
| `images` | nothing | builds every Sneakers service image, and the sneakers-migrate Job image, from the build block the pinned `release.yaml` gives it (the repository, the full commit, that repository's own Dockerfile and context, the target and build args), for linux/amd64, stamped with the service's version and commit, without provenance or SBOM attestations and with the layer times set to the commit's (`build/release/images.sh`); each is an OCI layout, pushed nowhere |
| `build` | nothing | checks out sneakers-release and sneakers-web at the pinned commits; puts each built service image's digest in place of its placeholder in `release.yaml` (`bundle fill`) and refuses, before the long build, a placeholder with no image built or any other image not pinned by a digest; renders the Sneakers stacks (above) and takes `product.yaml`; builds the kernel, the :8443 pages, the root image (with the pages), the unsigned UKI and systemd-boot, the production kit; fetches k0s and helm (checked against `release.yaml`) and the manifest of every pinned image (checked against its digest); takes the Base OS input digest; and writes `SHA256SUMS` over all of it (`build/release/build.sh`) |
| `sign` | the `production` environment | checks `SHA256SUMS` and the fingerprints; adds the update key to the UKI; signs the UKI and systemd-boot with the db key; countersigns `release.yaml` (with the built digests) and every pinned image's manifest with the release key; assembles and signs the artifact; builds the product bundle from the countersigned images (the service images from the `images` job's layouts), the Sneakers stacks and `product.yaml`, which the bundle check refuses without every component; seals the three units with `build/lab/units.sh` on the production channel, with a Base OS patch from the previous published release on the tag's channel (`sneakers-artifact release-previous` over the API's releases list; that release's Base OS is downloaded, verified with the production key and opened with the update key, and units.sh rebuilds the target from it and checks it before the patch is kept); signs the index and `SHA256SUMS` with the release key; writes the OVA with the production kit from the signed artifact and signs it; opens each the way the box does (the production kit checks the Base OS); each key is written to a tmpfs only in the step that uses it and removed there, and the tmpfs is unmounted at the end |
| `publish` | `packages: write`, `contents: write` | verifies the artifact with the production kit, each unit with the production key and every countersignature with `cosign verify-blob`, pushes every service image to the image `release.yaml` names (`ghcr.io/sneakers-pam/<service>`) by its digest, tagged with the version, and reads each back by that digest, pushes `sneakers-os` to GHCR, verifies what it pushed, checks every file is under 2 GiB, and attaches the units, the patch, their `.inputs`, the index, `SHA256SUMS` and their signatures, the OVA with its sum and signature, `release.yaml` and the countersignatures to the tag's GitHub Release (a draft when the owner made none, marked prerelease for an rc tag; nothing publishes it) |
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
`main`. The service images are built by this workflow from the commits sneakers-release's
`release.yaml` pins in each service's `build` block, so one appliance tag ships every image and no
service has to tag first; their digests stay `sha256:TBD-at-release` in git and the build job fills
them in. A placeholder with no image built for it is refused before the long build. (When the
services tag their own release images, the release can take those digests instead and drop the
`images` job.)

The k0s binary comes from its upstream release, checked against the pin in `release.yaml`, and goes
into the product bundle with the images, and so does helm's when `release.yaml` pins it. The first
production release ships full units only: no bridge copy and no patch (`build/lab/units.sh` refuses
`BRIDGE=1` on the production channel). Choosing only the units whose inputs changed since the last
release isn't in the workflow yet: every release builds all three. Every image in the product bundle is signed with the
release key, third-party ones included. amd64 only for now; arm64
follows its kernel build.
