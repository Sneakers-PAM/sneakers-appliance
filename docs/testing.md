# Testing

| What | Where | When |
|---|---|---|
| Unit tests (the chain, the writers, init, custody, Secure Boot, the upgrade stager) | `go test ./...` | every PR (`🧪 Build & Test`) |
| netd and the firewall in network namespaces (needs root) | `sudo -E go test ./internal/netd/ ./internal/firewall/` | every PR (`🧪 Build & Test`, with `SNEAKERS_REQUIRE_NETNS=1`) |
| sshd-run and the rendered config against the pinned static sshd | `SNEAKERS_TEST_SSHD=out/static/sshd go test -run 'Sshd\|Check' ./internal/sshconfig/ ./internal/sshdrun/` | every PR (`Static tools`) |
| Tool interop (efitools, cosign, sbsign, sbverify, unsquashfs, ukify against the kit's checks) | `go test -tags tools ./test/kit/labkeys/` | every PR (`🔑 Lab keys and tool interop`) |
| The root image: reproducible, the declared tree, its refusals | `bash build/root/build_test.sh` | every PR (`🔑 Lab keys and tool interop`) |
| The airgap bundle: pull by digest per architecture, signatures, both-way check (a `registry:2` container) | `go test ./internal/bundle/` | every PR (`🧪 Build & Test`) |
| The data move with the real tools against plain PostgreSQL containers: every row moved, TLS and password logins, and SIGKILLs mid-dump, mid-restore and before the switch, each back on the old data ([data-move.md](data-move.md#testing-it)) | `go test -tags integration ./internal/datamove/` | on every pull request, in the Go CI job (needs docker) |
| The disk guard on a real small volume: filled past 80% with removable files it recovers by itself; past 90% with a protected file it stays critical and touches nothing | `DISKGUARD_TEST_DIR=<a directory on a tmpfs or loop volume of 8 GiB or less> go test -tags integration -run Fill ./internal/diskguard/` | by hand (a tmpfs mount needs root; the test skips without the variable) |
| Kernel and static tools | `job-image-build.yaml` | PRs that touch their inputs |
| The image suite (QEMU, OVMF Secure Boot, swtpm) | `go test -tags image ./test/image/...` | after each merge to main, nightly at 07:17 UTC (03:17 ET), and on demand (`image-e2e.yml`); a merge never cancels the suite already running on main, it waits for it; a pull request only builds the lab release and reports the root image and product bundle sizes |
| The real Sneakers product through the update paths a box takes (QEMU, the real bundles) | `build/realci/build.sh`, then `go test -tags image -run 'TestTheRealBundles' ./test/image/k0s/` | after each merge to main, nightly at 05:41 UTC (01:41 ET), by hand, on a pull request that changes the job, and in the release workflow before anything is built (`real-bundle.yml`, [the real-bundle job](#the-real-bundle-job)) |
| The sign-off journeys in a real browser (headless Chromium against one booted box with the :8443 pages and the real product) | `build/journeys/build.sh`, then `go test -tags image -run TestTheSignOffJourneys ./test/image/journeys/` | pull requests that touch the image or the journeys, nightly at 07:17 UTC with the image suite, and on demand (`image-e2e.yml`, [the browser journeys](#the-browser-journeys)); never on a push to main |

Tests that need a tool skip with its name when it's missing; CI sets `SNEAKERS_REQUIRE_TOOLS=1`, so
there a missing tool fails instead.

## What a pull request runs

Every build, test, lint, licence and security workflow first calls `changes.yml`, which reads the
pull request's changed paths (`build/ci/changes.sh`):

- **Docs only** (every path is `*.md` or under `docs/`, which covers `AGENTS.md` and `CLAUDE.md`):
  only the scrub (`checks / scrub`), `✅ PR Checks` and the label checker run. Everything else
  skips: `🧪 Build & Test`, `🧹 GolangCI`, `🔑 Lab keys and tool interop`, `🔐 Gosec`,
  `🛡️ Govulncheck`, `🔏 License headers`, `⚖️ Dependency licenses (Go)`, Static tools, the Image
  E2E lab build, YamlLint and Actionlint. A job skipped by its `if:` reports success under its own
  name, so the required checks pass and the merge never waits. The kernel and static tools
  (`job-image-build.yaml`) and the real-bundle job only start on their own inputs anyway.
- **Anything else** runs everything, as before. YamlLint runs only when a YAML file (or
  `.yamllint`) changed, and Actionlint only when a workflow or a local action changed.
  [The browser journeys](#the-browser-journeys) run only when a path that goes into the image
  or its build changed (`os/`, `cmd/`, `internal/`, `gen/`, `build/`, `go.mod`, `go.sum`), or
  the journeys themselves (`test/e2e/journeys/`, `test/image/journeys/`, `test/image/harness/`,
  `image-e2e.yml`); Markdown under those paths doesn't count.
- **Not a pull request** (push to `main`, the nightly runs, the weekly Go Security run,
  `workflow_dispatch`, the release workflow's `workflow_call`): everything runs.

If `changes.yml` itself fails, the jobs after it run instead of skipping (their `if:` starts from
`!cancelled()`). `bash build/ci/docs_only_test.sh` checks the classifier and this wiring.

## The lab release

`build/lab/build.sh` builds a whole release the way the release workflow does, signed with a key
set `build/keys/lab-keys.sh` makes for that run only: the lab product bundle
(`build/product/build.sh`: the pinned k0s, `K0S_VERSION` in `build/ci/versions.env`, the images in
`build/lab/images.txt`, each digest signed with the run's key, and the stacks in `build/lab/stacks`,
the throwaway hello stack and the interim edge, [k0s.md](k0s.md)), sealed as
`product/sneakers-product-lab-<label>-amd64.bin` with its index; the root image (`build/root/build.sh`,
with no k0s or images, the static OpenSSH and busybox, and the static cryptsetup, veritysetup,
mkfs.ext4 and sgdisk from `STATIC`, which first boot needs to make the state volumes, and the root
shell's `watch` with its terminfo entries, plus
`build/lab/overlay`: the image suite's hook), the
UKI (`build/uki/assemble.sh`, signed with `sbsign`), systemd-boot (signed), the enrolment
material, `release.yaml` and the artifact (`sneakers-artifact assemble`, then `cosign sign-blob`
over the index blob and `sneakers-artifact attach`). It then builds a kit pinned to that run's keys
and writes the raw disk with it, so every PR runs the kit's whole chain against a real release.
Its version carries the build number, the short commit it was built from in git-describe form
(`VERSION=0.0.0-lab.20261007d` from commit `1a2b3c4` builds `0.0.0-lab.20261007d.r<UTC time>-g1a2b3c4`),
which the signed headers and the index carry; a file name carries only the build's label
(`sneakers-appliance-lab-d-amd64.raw`, the `.ova` and the `.bin` likewise,
[release.md](release.md#file-names)). The version it used is in `$OUT/version`. In
CI the keys live on a tmpfs that's unmounted at the end of the job; nothing built is uploaded.

**The three units.** `build/lab/units.sh` then makes a lab build's update units (spec 7) from its
output with the same keys: `OUT=<build output> KEYS=<keys> bash build/lab/units.sh` writes, in
`$OUT/units` (or `UNITS`), the Base OS full `.bin` (`BRIDGE=1` also writes it under the old name and
lists it in the index's legacy base section, for boxes from before the units; `OLD_NAMES=1`, the lab
default, links every unit under the name earlier builds gave it too, so a box running one finds its
update in the index), the Base Web `.bin`
(when the build made pages, `WEB`), the product bundle, a Base OS patch from each build output in
`PATCH_FROM`, and the format 2 index over them all (and over the `.bin` files of the directories in
`INDEX_ALSO`). `CHECK_FROM` makes a patch that's built and checked but goes to `checked-only/`, out
of the index. Every patch is opened as a box on its base opens it (that build's signed UKI),
rebuilt from the base artifact with the box's own code (`sneakers-artifact patch-check`), and the
rebuilt layout verified by both builds' kits (the target's is `$OUT/sneakers-kit`, or `KIT`; without an executable one a patch is refused before anything is sealed). Each `.bin` has its input digest beside it
(`<file>.inputs`, also in its signed header): `units.sh inputs baseOS` (the appliance tree and the
components in `KERNEL`, `VERITYSETUP`, `OPENSSH`, `BUSYBOX` and `STATIC`), `inputs baseWeb` (the
built pages, `PAGES`) and `inputs product` (every file `build/product/build.sh` makes the bundle
from: `RELEASE`, the image digests and pins, `STACKS`, `PRODUCT_YAML`, which defaults to
`build/lab/product.yaml`, `IMPORT_JOB` and `BRAND`; a named file that isn't there is refused),
for a release job to compare with the last published release. The product bundle's `.inputs` is
read from its own header (`sneakers-artifact bin-inputs`), so it's the digest it was built with. `build/lab/units_test.sh` checks the
digests. From build m the root image is an uncompressed SquashFS (`build/root/build.sh`), so a
delta between two roots stays small; the `.bin` payload isn't compressed yet, so a Base OS full
file carries the root at its full size.

`build/keys/lab-keys.sh` refuses to touch a `KEYS` directory that already holds a key set, so a
build pointed at a shared, on-disk lab key folder can never silently replace its private keys:
`NEW_KEYS=1` replaces the set on purpose, `REUSE_KEYS=1` keeps it as is (refused if the set is only
partial, e.g. an interrupted earlier run). CI always passes a fresh, empty tmpfs directory, so
neither flag is needed there. Every lab build records which key set it used in `$OUT/keys.txt`,
the SHA-256 fingerprint of PK, KEK and db (the certificate), the release cosign key and the update
key's recipient, in the `fingerprints.txt` format
[production-keys.md](runbooks/production-keys.md) and `build/release/check-fingerprints.sh` use
for a production key set.

The :8443 pages come from sneakers-web, and `WEB` is the supported way to put them in a lab image.
With `WEB` naming a sneakers-web checkout, the lab build builds them itself (`build/lab/pages.sh`:
`npm ci --ignore-scripts`, then the appliance admin's build with `APP_VERSION` set to the lab
version and `APP_COMMIT` to the checkout's short commit) and refuses pages that come out without
that stamp, so About and diagnostics on the box name the build. The release workflow's lab job
passes `WEB` at the commit `build/release/pins.env` pins. A lab build refuses `OSADMIN_ASSETS`,
because pages built elsewhere can say `0.0.0 (unknown)`, and refuses to run without `WEB` unless
`NO_PAGES=1` says it's for a test that never serves the pages (the image suite and the real-bundle
job). `build/lab/pages_test.sh` checks the stamp with a stand-in npm, and `build/lab/build_test.sh`
checks the refusals.

## The QEMU harness

`test/image/harness` boots a disk on q35 with SMM and OVMF's Secure Boot build and a vars store in
one of three states (`virt-fw-vars`): the run's lab PK, KEK and db enrolled and enforcing
(`Enrolled`), empty for Setup Mode (`Off`), or the keys enrolled with `SecureBootEnable` off
(`OffWithKeys`, a VMware VM with Secure Boot off). `NoSecureBoot` boots OVMF built without Secure
Boot (`SNEAKERS_OVMF_CODE_NOSB`, Ubuntu's `OVMF_CODE_4M.fd`), so the box sees no Secure Boot
variables at all, like the first lab target. It adds swtpm as the TPM when asked and uses KVM
when the runner has it. The serial line is a pair of FIFOs: the output goes to a file the tests
match against, without its colour codes, and `Type` sends console input. `Stop` kills the VM,
`WaitExit` waits for a guest reboot (QEMU runs with `-no-reboot`), and `Disk` hands the VM's disk
to the next boot (copied, or with `Disk.Move` renamed, for a disk too big to copy at every boot).
`CPUs` sets the virtual CPUs (2 by default). On a failure the last lines of the console go to the test log and the job
summary.

For the Proxmox VE shape, `Disk.Format` takes a qcow2, `SCSI` puts each disk on its own VirtIO SCSI
controller (`virtio-scsi-single`), and `GuestAgent` adds the `org.qemu.guest_agent.0`
virtio-serial port; `Agent` sends one command to the guest agent after a `guest-sync-delimited`
and returns its reply, and `AgentNoReply` sends one that answers with nothing (`guest-shutdown`).
`Vars` and `TPMState` hand a boot's vars store and TPM state to the next boot, so keys the box
enrolled and state it sealed carry over a reboot.

Every VM has a QMP socket. `NoSerial` boots without a serial port and `NoVGA` without a display
adapter. `ExpectScreen` reads the display from a QMP screendump: each 8x16 cell is matched
against fbcon's font, which the harness reads out of the kernel the image boots (`SNEAKERS_KERNEL`,
the bzImage; it needs the `xz` tool), and the rows are joined as they wrap. `Press` types on the
VM's keyboard. For a reader on another goroutine (the browser journeys' console reader),
`ReadScreen` reads the display without failing the test, `ScreenText` joins its rows the way
`ExpectScreen` matches them, `Screendump` answers the raw PPM, and `Exited` is closed once QEMU
has exited.

`Stable` watches the console for a while after the banner. It fails if init stops (`init: fatal`,
a kernel panic) or QEMU exits, and if any service restarts three times or more. A service that's
known to crash-loop on the image is named with its reason, and it fails once it stops looping, so
the entry goes when its cause is fixed. Today there are none.

## The real-bundle job

The image suite boots the lab product, a hello page and stand-ins. The real-bundle job
(`.github/workflows/real-bundle.yml`) boots the real Sneakers product, built the way the published
lab bundles were, through the update paths a box takes, so a break between the real pieces
(the phases, the box values and the switches together, or a product without phases updating to one
with them) fails here and not on a box.

**The builds** (`build/realci/build.sh`, LAB ONLY, one lab key set made for the run on a tmpfs):

| Piece | Built from |
|---|---|
| the old base (the boxes' n6) | `build/lab/build.sh` at `OLD_BASE_COMMIT` (`build/realci/pins.env`), its raw disk |
| the base under test (n7) | `build/lab/build.sh` at the commit under test, packed as a Base OS update (`sneakers-artifact bin-pack`, as the release workflow's lab job does) |
| `.12`, the product without phases | this repository at `P12_APPLIANCE_COMMIT` with sneakers-release at `P12_RELEASE_COMMIT` |
| `.13`, the first with phases | `P13_APPLIANCE_COMMIT` with `P13_RELEASE_COMMIT` |
| `next`, the product under test (`0.1.0-lab.realci.next`) | the commit under test with `NEXT_RELEASE_COMMIT` (empty: sneakers-release's main) |
| the import leg's `sneakers-migrate`, for the runner | the commit next's `release.yaml` pins for the migrate image (`spec.jobs.migrate`), so the export writes a bundle format the box's steps read |
| the import leg's `synth`, for the runner | next's sneakers-release commit |

Each product is the release path with lab keys (`build/realci/product.sh`, run in its own
commit's checkout with that commit's tools): the service images from `build/release/images.sh`
(each from the commit its release.yaml pins; the builds are reproducible, so `.13`'s are
byte-identical to the published `.13`'s), `bundle fill`, each pinned manifest signed with the lab
key, the production render with the lab's debug log level, product.yaml and the import Job, then
`build/product/build.sh`. The stacks match the published bundles but for the version; only the
generated box secrets differ, as on any new box. Every base is built by its own commit's scripts
with this commit's lab hook, so the test reads the same lines from each. The service images are
cached by the sneakers-release commit they're built from; the bases and the bundles are built and
signed every run ([the caches](#the-caches)).

**The lab hook's real-product path.** With the Sneakers product installed (a `sneakers` stack), the
hook ([k0s.md](k0s.md)) writes 1000 rows into a `realci_rows` table in each of the product's six
databases once the box first runs it (once per box), through the root's `kubectl exec` into the
bundled PostgreSQL. At each boot it prints the state volume's mount options. Each time the box runs a product version it hadn't reported since the boot, it
prints the rows of every table in every database, how PostgreSQL's current start began (`first`,
`clean` or `recovered`), and the product's pods (phase order, restarts, each init container's
restarts and end, why a container waits, start and Ready times).
While the box doesn't run, it prints the box's state, the pods, each `wait-phase` init container's last lines, each
crash-looping container's last lines and the rows every five minutes. Every minute it prints the
box's memory (`realci: memory`: MemTotal and MemAvailable, what the product's pods use, the running
import step's peak so far) and each product container that restarted, with how its last run ended
(`realci: restarted <container>=<restarts>/<reason>/<exit code>`). Every five seconds it reads the
running import step's `memory.peak`, and prints the peak once the step's pod is gone
(`realci: import peak`).

**The legs** (`test/image/k0s/realbundle_test.go` and `realbundle_import_test.go`, 8 GiB, the import leg 12 GiB, and 4 CPUs, 22, 8443 and 443 forwarded):

| Leg | Test | What it checks |
|---|---|---|
| upgrade | `TestTheRealBundlesUpdateInOrder` | the old base with `.12` and `sneakers mcp on` over SSH; the Base OS update to the base under test; `.12` to the product under test (no phases to phases); then a power loss. After each step the box runs the product within 45 minutes (else it's stuck: the failure names what holds it, such as a `wait-phase` init container backing off, with the hook's last lines); for a phased product every phase (data, identity, services, front) has a pod and each pod started only once the phases before it were Ready; no running pod or init container restarted, every init container (a phase's `wait-phase` among them) completed, and each pod is Ready; the MCP server runs; every database still counts, the 1000 rows are in each, no table that held rows has fewer, and PostgreSQL didn't start on a new data directory. After the power loss no pod is one from before it, restarted in place, and the state volume is mounted `nodelalloc` ([disk-layout.md](disk-layout.md)) |
| recover | `TestTheRealBundlesRecoverFromAStuckUpdate` | the old base with `.12` and the MCP switch on, then `.13` on the old base, which that base doesn't bring up: the test records whether it got stuck, and if so the hook's lines and whether the rows were already short in that state. Then the base under test is applied in that state, and whether it brings `.13` up by itself is recorded (it can't: `.13`'s own data-phase wait fails, with the `wait-phase` lines in the log); the box must then take the product under test and run it with the checks above |
| import | `TestTheRealBundleImportsALargeAuditChain` | a new box (12 GiB) on the base under test's raw disk, with the product under test installed and running. The source is sneakers-release's synthetic source with a 727,000-record audit chain, more than the largest source measured (`build/realci/source.sh`): PostgreSQL and Kratos containers on the runner, seeded by the release's `synth` while the box comes up. It is exported to the box's import key as the appliance move takes it, named `source.example.org` where that `sneakers-migrate` takes `--source-name`, then taken through the Import page's API: open, upload, review, convert (a proposal sheet that renames one secret), check, import with the first admin's email and its one-time password, and verify. Each step must pass, and the box ends in imported-users mode. With a migrate image that writes bundle format 2.0, the leg also checks that the audit trail stayed on the source: the export and the import list it as not carried, the review says so, the import names the source and wrote one audit record, and verify finds the box's chain starting with that record. With an older image the chain moves in the bundle (37 MB), and the leg logs that it did. The leg logs each step's time and peak memory, and the box's memory with the product running and with the import open ([import.md](import.md#memory) has the numbers) |
| control | the upgrade test with `CONTROL=1` | the base under test is `CONTROL_COMMIT`, from before the quiesce fixes (#365, #370): the update to phases must fail there. The leg is allowed to fail (`continue-on-error`); it runs on pull requests and by hand |

A leg takes up to about an hour and a quarter on a GitHub runner (the builds about 3 minutes when
the next product's service images are cached, about 10 when they aren't; the boots and updates 15
to 60 minutes; a wait ends early once the box has said `failed` three
reports in a row), so the job doesn't gate every pull request. The import leg takes about half an
hour: about 10 to 13 minutes for the builds, and about 12 for the box's first boot, the install,
the import and the close. The source's seeding (4 to 9 minutes) runs while the box comes up, and
each step takes under a minute (the import 46 seconds). It runs as its own leg next to the others, on pull requests that change the job,
on main, nightly and in the release gate. A run by hand takes `under_test`, the commit
whose base and product to test. Only logs leave the run (the serial consoles, the build logs and the
`go test` output, as the `real-bundle-logs-<leg>` artifact); nothing built and no key is uploaded.

### The caches

The repository is public, and a run from a fork can restore what a run on main cached, so the job
caches nothing a key signed and no key. It caches only what no key goes into:

| Cache | Key | What's in it |
|---|---|---|
| the kernel and the static tools | the hash of their sources and `build/ci/versions.env` (shared with the image suite) | `build/out/kernel/amd64`, the static cryptsetup, e2fsprogs, gptfdisk, watch and qemu-ga in `build/out`, OpenSSH and busybox in `out/static` |
| the old base's own static tools | `realci-components-<OLD_BASE_COMMIT>` | the tools its tree builds when its stamps differ |
| `.12`'s and `.13`'s service images | `realci-images-<P12_RELEASE_COMMIT>-<P13_RELEASE_COMMIT>-<hash of build/release/images.sh>` | their OCI layouts, unsigned (the public images) |
| the next product's service images | `realci-images-next-<sneakers-release commit>-<hash of build/release/images.sh and build/tools/bundle/>` | its OCI layouts, unsigned |

The lab key set is made for each run on a tmpfs, and the old base, the base under test and the
`.12`, `.13` and next bundles are built and signed with it every run, and checked with it as
[the builds](#the-real-bundle-job) say. Their unsigned parts can't be kept apart from that: the old
base's root carries the run's public keys (the release key and the Secure Boot certificates, built
into its binaries), so its verity hash and UKI follow them, and each product's payload is encrypted
to the run's update key. Together they take about two minutes. Next's images are resolved to a
sneakers-release commit in the job's first steps (`NEXT_RELEASE` for `build/realci/build.sh`) and
saved straight after the build, so a failing leg still fills the cache.

Before anything is saved, `build/realci/no-keys.sh` checks every path the job caches (`build/out`,
`out/static` and the image and component folders) and fails the leg on a `*.key` file, a PEM
private key, an age identity or any line of the run's own private keys; the step summary lists
each path, its file count and size. `build/realci/cache_test.sh` (in the Go CI job) checks
no-keys.sh and that the workflow caches no other path.

**To bust a cache**, change its key's inputs, or delete it: `gh cache list --key realci-images-`
and `gh cache delete <key>`.

## The browser journeys

The sign-off journeys a person otherwise clicks through by hand, walked in headless Chromium
against one booted box on the GitHub runner (the `🧭 Browser journeys (amd64)` job in
`image-e2e.yml`). Nothing runs a browser on a workstation.

**The builds** (`build/journeys/build.sh`, LAB ONLY, one lab key set made for the run on a tmpfs):
a lab release of the commit under test with the :8443 pages built from sneakers-web at
`SNEAKERS_WEB_COMMIT` (`build/release/pins.env`, [the lab release](#the-lab-release)), and the real
Sneakers product from sneakers-release at `SNEAKERS_RELEASE_COMMIT`, built the way [the real-bundle
job](#the-real-bundle-job) builds its products (`build/realci/product.sh`) and sharing its cache of
the service images (`realci-images-next-<commit>-...`), sealed and checked with the lab UKI. Every
cached path is checked for keys before it's saved, as there ([the caches](#the-caches)).

**The box** (`test/image/journeys`, `TestTheSignOffJourneys`): a new box from the lab raw disk with
VGA and a serial line, the run's keys enrolled with Secure Boot off and no TPM (a VMware VM), 8 GiB
and 4 CPUs. The driver types the boot's own choices at the console (`no secure boot`, then Enter at
the key file); everything after that is the browser's. The browser goes to the address the console
shows, the first lease on QEMU's user network, through a proxy the driver runs: it takes CONNECT to
that address's 8443 and 443 only and passes each to QEMU's forward of that port on the runner's
loopback. TLS runs end to end through it, so the browser checks the box's certificate itself. (A
forward bound to the lease's own address on the runner doesn't work: QEMU would hand the box
connections from its own address.) The box's mail relay is a Mailpit container on the runner
(`build/journeys/mail.sh`, pinned by digest), reached through a guest forward on QEMU's user
network (port 2525), with STARTTLS required on a certificate from a CA made for the run. The driver
serves the console's display to the journeys, read off QEMU, so they read the setup code and the
certificate fingerprint where a person reads them, and it boots the box again when it restarts.

**Certificate checks stay on.** Before the browser starts, the journeys fetch the box's :8443
certificate, check its SHA-256 fingerprint against the one on the console (once the two have agreed
for 30 seconds: a new box makes its certificate again as its SLAAC address comes in after its DHCP
one, and the console follows), and start Chromium with that certificate's key pinned
(`--ignore-certificate-errors-spki-list` with its SPKI hash), so the browser takes the box's own
certificate and checks every other one as usual. `ignoreHTTPSErrors` is never used. The first-run
journey checks the certificate again after the restart, and the product journey checks that 443
serves the same one.

**The journeys** (`test/e2e/journeys`, Playwright at the exact version its lockfile pins, run in
order, each on what the one before left):

| Journey | What it checks |
|---|---|
| `01-first-run-setup` | the console shows the :8443 address, its certificate and a setup code; on :8443 the code, the first admin's name, password and authenticator (the TOTP code made from the key the page shows), a recovery key the box generates (downloaded), the network and protection steps, then one sign-in and Finish; the box restarts into normal operation (the console's status screen), keeps its certificate, and the admin signs in |
| `02-updates` | Updates set to Manual only, the real product bundle uploaded under Install an update, Verify and stage (its signature verified against the box's release key), Apply update with the version typed and a fresh code, until the Product card shows it running |
| `03-email` | the Email page's relay set to the mail catcher with STARTTLS, Verify the certificate on and the run's CA as the Relay CA (no unencrypted warning), saved with a step-up; Send test email, and the message arrives at the catcher |
| `04-product-sign-in` | 443 serves the certificate the console shows; the setup token read with Show on :8443's Status page, which names this box's /admin/setup; the admin web's first admin, the built-ins, and the emailed code that verifies the address; then a sign-in to the admin web and one to the staff web, each with the second step the product asks for (an authenticator it has the admin set up, or an emailed code) |
| `05-network` | the Network page shows the box's address, and Run checks shows its link and address OK |
| `06-backups` | the Backups page opens; a backup run and its new set are skipped, with the reason, while the box serves BackupService as not available in this release |
| `07-add-ons` | the add-on modules' on and off switches: stubs, skipped with the reason, until the add-ons land |

Every journey keeps a Playwright trace and a screenshot after each step (the authenticator keys,
QR codes and setup token are masked in the screenshots). A failing step fails the job, and only
then are they uploaded with the HTML report and the box's serial consoles as the run's
`browser-journeys` artifact, kept for 1 day. A passing run uploads nothing; its step summary lists
the journeys. The traces hold the run's throwaway credentials, made in the run for a box that only
existed inside it; nothing built and no key is uploaded.

To read a failed run's artifact, within the day:

1. Download the artifact: `gh run download <run id> -R Sneakers-PAM/sneakers-appliance -n browser-journeys -D journeys`.
2. Open the report: `npx playwright show-report journeys/playwright-report`. Each journey lists its steps, with the screenshots attached in step order.
3. Open a journey's trace, to step through every action with the page before and after it: `npx playwright show-trace journeys/test-results/<journey>/trace.zip`.

The serial consoles are `journeys/logs/journeys-boot<n>.log`, `journeys/logs/go-test.log` has
the driver's and Playwright's output, and `journeys/build/` the builds' logs.

To change a journey, run `npm ci --ignore-scripts`, `npm run typecheck` and `npm run test:units`
(the TOTP codes and the console reading, no browser) in `test/e2e/journeys`. The driver's proxy and
screendump reading have their own tests in `go test ./test/image/journeys/`. The journeys need the
box, so they run only in CI (or `go test -tags image ./test/image/journeys/` on a Linux host with
the builds and a mail catcher).

## The image suite

The `k0s` tests' first boot sets the box's update policy to `manual` once setup is done: they
stage and apply every update themselves, and a new box's automatic window (02:00 for 2 hours, box
time, which is UTC on CI) would otherwise apply what a test just staged first, so a run in that
window failed with `UPGRADE_NOT_STAGED`.

| Test | What it boots | What it checks |
|---|---|---|
| `harness.TestHarnessBootsToSerialBanner` | Secure Boot enforcing (lab keys), swtpm | `phase=firstboot` |
| `harness.TestFirstBootStaysUp` | as above | Enter at the protection step keeps the TPM; the state is formatted and mounted, protection is full, accessd is ready, and nothing crash-loops |
| `reduced.TestNoSecureBootNoTPMBootsReduced` | no swtpm; an empty vars store, and keys enrolled with Secure Boot off | the Secure Boot choice (no default outside Setup Mode: Enter alone re-prompts), the typed `no secure boot`, then the key file at the protection step and first boot; after a kill, the next boot is `protection=reduced (Secure Boot off)` without asking either again |
| `console.TestTheScreenAloneShowsTheChoiceThenTheSetupInfo` | no serial port, VGA, keys enrolled with Secure Boot off, no swtpm (a VMware VM) | the Secure Boot choice on the screen with none of init's or the services' lines on it (the banner goes to the serial line and the console log), `no secure boot` typed on its keyboard, then Enter at the protection step (key file); then first boot owns the screen and asks nothing: read off the screen in the large font, the :8443 address on QEMU's DHCP lease, a setup code of the form `XXXX-XXXX-XXXX-XXXX` and `Protection REDUCED` |
| `k0s.TestTheProductBundleBringsK0sAndTheHelloStack` | no swtpm, Secure Boot off with keys, 4 GiB, the lab hook's marker on the ESP, 22, 8443, 443 and 80 forwarded, the lab product bundle (`SNEAKERS_PRODUCT`) | the whole first boot (as `setup`); in normal operation the kernel host name is the box's own `sneakers-<8 hex>` (QEMU's DHCP offers none), no k0s runs and 443 doesn't answer; the bundle is uploaded, staged and applied through the Updates API; k0s starts from it, the node, the hello pod and the edge are Ready, the root shell's `kubectl get nodes` and `helm list -A` work through the root's links with its `KUBECONFIG`, `watch` runs and its terminfo entries are there, `https://<box>/` answers `hello from sneakers-appliance`, 80 redirects to https, SSH and :8443 answer, `GetUpgrades` shows the product running, a pod's outbound connection leaves the box from its NIC's address (the hello pod connects to an address QEMU forwards to the host while the NIC is captured; [network.md](network.md#pod-egress)), and k0s doesn't crash-loop ([k0s.md](k0s.md)) |
| `k0s.TestBlueTakesRedFromUpdatesAndRevertsToBlue` | no swtpm, Secure Boot off with keys, 22 and 8443 forwarded; two lab builds of one commit, BLUE (`SNEAKERS_IMAGE`, `SNEAKERS_BLUE_VERSION`) and a newer RED as its update `.bin` (`SNEAKERS_RED`, `SNEAKERS_RED_VERSION`), signed with the same lab keys | the whole first boot on BLUE; RED is uploaded and staged as a base update (its ESP entry with 3 tries), applied, and boots in the normal phase with its version on the console; once it's up, RED's entry loses its boot counter (marked good, [upgrades.md](upgrades.md)); a revert marks RED bad and BLUE boots again in the normal phase. The ESP is read with `mdir`. The image workflow builds one lab release, so there it skips; run it by hand on a BLUE and RED pair |
| `k0s.TestThreeUpdatesInARowKeepTwoReleases` | no swtpm, Secure Boot off with keys, 22 and 8443 forwarded; lab builds of one commit signed with the same lab keys: the image (`SNEAKERS_IMAGE`, `SNEAKERS_BLUE_VERSION`) and at least two newer builds as update `.bin`s, in order (`SNEAKERS_UPDATES` and `SNEAKERS_UPDATE_VERSIONS`, comma-separated) | retention ([upgrades.md](upgrades.md)): each update is uploaded, staged, applied and marked good in turn; after every stage the ESP holds only the running release and the staged one; from the second update on the ESP (copied out with `mcopy`) stays within 1 MiB and the state volume (`GetStatus` disk use) within 96 MiB of the first update, where a leaked `.bin` or fetched release is the size of a root image; before each stage `GetUpgrades.next_stage_removes` names the release two back (nothing on the first update); the last release is then reverted and the one before it boots. Skips without the builds, as in the image workflow |
| `k0s.TestTheDatabaseKeepsEveryRow` | no swtpm, Secure Boot off with keys, 4 GiB, the lab hook's marker on the ESP, 8443 forwarded, the two durability bundles (`SNEAKERS_DURABILITY_PHASELESS`, `SNEAKERS_DURABILITY_PHASED`, `build/lab/durability.sh`) | the bundled PostgreSQL from sneakers-release's chart keeps every row: 10000 rows written after the install without phases, counted again after the update to phases, a reboot (the quiesce) and a power loss; the database's start after the update and the reboot is a clean one, not a crash recovery ([k0s.md](k0s.md)) |
| `setup.TestFirstBootToAWorkingAppliance` | VGA and no serial port, keys enrolled with Secure Boot off, no swtpm, QEMU's user network with 22 and 8443 forwarded (a VMware VM) | the whole first boot: the console asks nothing after the boot's own choices and shows the :8443 address on the DHCP lease and the setup code, read off the screen; on :8443 the code makes the first admin with a password and TOTP, sshd answers only once the admin exists, the box issues an SSH key, a recovery key is set, the single admin is confirmed and one sign-in finishes setup; the console completes it and restarts by itself; after the restart the status screen shows the admin page, SSH takes the issued certificate and a TOTP code, `status` says `normal`, and :8443 serves with the certificate `status` names |
| `console.TestTheSerialLineAloneShowsTheChoiceAndTakesTheAnswer` | no display adapter, as above otherwise (a headless box) | the same on the serial line |
| `console.TestBothConsolesShowTheChoiceAndTheScreenCanAnswer` | serial and VGA | the choice on both; the answer typed on the screen's keyboard is taken while the serial line shows it |
| `reset.TestAResetFinishesAtBootThenFirstBootIsFresh` | Secure Boot enforcing, swtpm; the disk laid out as after first boot, with a begun reset record on the ESP | `phase=reset` finishes the reset and reboots without starting services; the key file, state and backup are out of the GPT and the record is `done`; the next boot is first boot (the protection step again), with no reset |
| `custody.TestKeyFileCustodyWithoutSecureBootOrTPM` | firmware without Secure Boot, no swtpm (the first lab target) | first boot keeps the key in the key file, formats and mounts the state, accessd is ready and nothing crash-loops; the next boot reads the mode back from the LUKS2 header and asks nothing; with the key file wiped, the boot stops at "State locked" with `KEYCUSTODY_LOCKED` and starts no service |
| `proxmox.TestProxmoxShape` (item 10) | the kit's qcow2 (`SNEAKERS_QCOW2`, written by the lab kit in the workflow) on its own VirtIO SCSI controller, an empty vars store (Setup Mode, Proxmox's `pre-enrolled-keys=0`), swtpm and the guest agent port | Enter at the Secure Boot choice enrols the org keys and the box restarts by itself; with the vars and TPM state carried over, the next boot is `phase=firstboot protection=full`, Enter keeps the TPM and first boot starts; the guest agent answers `guest-ping` and `guest-network-get-interfaces`, and refuses `guest-exec`, `guest-exec-status`, `guest-file-open`, `guest-set-user-password` and `guest-ssh-add-authorized-keys` as disabled; `guest-shutdown` drains the services and powers the box off, and QEMU exits. Proxmox VE itself isn't in CI: [proxmox-vm.md](proxmox-vm.md) is untested on a real host until one runs it |
| `ova.TestFreshOVAFirstBoot` | the disk inside the kit's OVA (`SNEAKERS_OVA`), converted to raw, on a SCSI controller, an empty vars store (Setup Mode) and swtpm | Enter at the Secure Boot choice enrols the keys on the disk and the box restarts by itself; the next boot is `phase=firstboot protection=full`, Enter keeps the TPM, the state and backup volumes are formatted and mounted, and first boot starts. The release workflow runs it on the production OVA in the `ovaproof` job and on a lab OVA in the `lab` job. QEMU stands in for VMware: the OVF descriptor and vApp properties aren't exercised here |
| `network.TestFirstBootGetsADHCPAddressAndKeepsSSHClosed` | no display adapter, keys enrolled with Secure Boot off, no swtpm; host port forwarded to the guest's 22 | netd takes QEMU's DHCP lease with no setting made (its `management addresses` line on the console), SSH gives no banner before the first-boot SSH step, and nothing crash-loops |


Once first boot owns the consoles, the services' own lines go to `/run/sneakers/console.log`
instead of the serial line, so the suite's crash-loop check (`Stable`) sees only what's printed
before first boot starts and its own restarts.

The screen is read from QEMU's screendump in whichever of the kernel's built-in fonts reads it
best: the large Terminus 16x32 the UKI selects, or the 8x16 the firmware and a small screen use.
Both are read out of the kernel under test, so there's no copy of a font in this repo.

Not in the suite yet: an elevation through the real sshd (request, approval, certificate login, the
time box, revocation).
