# Testing

| What | Where | When |
|---|---|---|
| Unit tests (the chain, the writers, init, custody, Secure Boot, the upgrade stager) | `go test ./...` | every PR (`🧪 Build & Test`) |
| netd and the firewall in network namespaces (needs root) | `sudo -E go test ./internal/netd/ ./internal/firewall/` | every PR (`🧪 Build & Test`, with `SNEAKERS_REQUIRE_NETNS=1`) |
| sshd-run and the rendered config against the pinned static sshd | `SNEAKERS_TEST_SSHD=out/static/sshd go test -run 'Sshd\|Check' ./internal/sshconfig/ ./internal/sshdrun/` | every PR (`Static tools`) |
| Tool interop (efitools, cosign, sbsign, sbverify, unsquashfs, ukify against the kit's checks) | `go test -tags tools ./test/kit/labkeys/` | every PR (`🔑 Lab keys and tool interop`) |
| The root image: reproducible, the declared tree, its refusals | `bash build/root/build_test.sh` | every PR (`🔑 Lab keys and tool interop`) |
| The airgap bundle: pull by digest per architecture, signatures, both-way check (a `registry:2` container) | `go test ./internal/bundle/` | every PR (`🧪 Build & Test`) |
| Kernel and static tools | `job-image-build.yaml` | PRs that touch their inputs |
| The image suite (QEMU, OVMF Secure Boot, swtpm) | `go test -tags image ./test/image/...` | after each merge to main, nightly at 07:17 UTC (03:17 ET), and on demand (`image-e2e.yml`); a pull request only builds the lab release and reports the root image and product bundle sizes |

Tests that need a tool skip with its name when it's missing; CI sets `SNEAKERS_REQUIRE_TOOLS=1`, so
there a missing tool fails instead.

## The lab release

`build/lab/build.sh` builds a whole release the way the release workflow does, signed with a key
set `build/keys/lab-keys.sh` makes for that run only: the lab product bundle
(`build/product/build.sh`: the pinned k0s, `K0S_VERSION` in `build/ci/versions.env`, the images in
`build/lab/images.txt`, each digest signed with the run's key, and the stacks in `build/lab/stacks`,
the throwaway hello stack and the interim edge, [k0s.md](k0s.md)), sealed as
`product/sneakers-product-<version>-amd64-LAB.bin` with its index; the root image (`build/root/build.sh`,
with no k0s or images, the static OpenSSH and busybox, and the static cryptsetup, veritysetup,
mkfs.ext4 and sgdisk from `STATIC`, which first boot needs to make the state volumes, plus
`build/lab/overlay`: the image suite's hook), the
UKI (`build/uki/assemble.sh`, signed with `sbsign`), systemd-boot (signed), the enrolment
material, `release.yaml` and the artifact (`sneakers-artifact assemble`, then `cosign sign-blob`
over the index blob and `sneakers-artifact attach`). It then builds a kit pinned to that run's keys
and writes the raw disk with it, so every PR runs the kit's whole chain against a real release.
Its version carries the build number, the short commit it was built from in git-describe form
(`VERSION=0.0.0-lab.20261007d` from commit `1a2b3c4` builds `0.0.0-lab.20261007d-g1a2b3c4`), so
every lab file name says which commit it is (`sneakers-0.0.0-lab.20261007d-g1a2b3c4-amd64-LAB.raw`,
the `.ova` and the `.bin` likewise); the version it used is in `$OUT/version`. In
CI the keys live on a tmpfs that's unmounted at the end of the job; nothing built is uploaded.

`build/keys/lab-keys.sh` refuses to touch a `KEYS` directory that already holds a key set, so a
build pointed at a shared, on-disk lab key folder can never silently replace its private keys:
`NEW_KEYS=1` replaces the set on purpose, `REUSE_KEYS=1` keeps it as is (refused if the set is only
partial, e.g. an interrupted earlier run). CI always passes a fresh, empty tmpfs directory, so
neither flag is needed there. Every lab build records which key set it used in `$OUT/keys.txt`,
the SHA-256 fingerprint of PK, KEK and db (the certificate), the release cosign key and the update
key's recipient, in the `fingerprints.txt` format
[production-keys.md](runbooks/production-keys.md) and `build/release/check-fingerprints.sh` use
for a production key set.

The :8443 pages come from sneakers-web. With `WEB` naming a sneakers-web checkout, the lab build
builds them itself (`build/lab/pages.sh`: `npm ci --ignore-scripts`, then the appliance admin's
build with `APP_VERSION` set to the lab version and `APP_COMMIT` to the checkout's short commit)
and refuses pages that come out without that stamp, so About and diagnostics on the box name the
build. `OSADMIN_ASSETS` still takes pages built elsewhere, which say `0.0.0 (unknown)` unless that
build set both variables. `build/lab/pages_test.sh` checks the stamp with a stand-in npm.

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
to the next boot. On a failure the last lines of the console go to the test log and the job
summary.

Every VM has a QMP socket. `NoSerial` boots without a serial port and `NoVGA` without a display
adapter. `ExpectScreen` reads the display from a QMP screendump: each 8x16 cell is matched
against fbcon's font, which the harness reads out of the kernel the image boots (`SNEAKERS_KERNEL`,
the bzImage; it needs the `xz` tool), and the rows are joined as they wrap. `Press` types on the
VM's keyboard.

`Stable` watches the console for a while after the banner. It fails if init stops (`init: fatal`,
a kernel panic) or QEMU exits, and if any service restarts three times or more. A service that's
known to crash-loop on the image is named with its reason, and it fails once it stops looping, so
the entry goes when its cause is fixed. Today there are none.

## The image suite

| Test | What it boots | What it checks |
|---|---|---|
| `harness.TestHarnessBootsToSerialBanner` | Secure Boot enforcing (lab keys), swtpm | `phase=firstboot` |
| `harness.TestFirstBootStaysUp` | as above | Enter at the protection step keeps the TPM; the state is formatted and mounted, protection is full, accessd is ready, and nothing crash-loops |
| `reduced.TestNoSecureBootNoTPMBootsReduced` | no swtpm; an empty vars store, and keys enrolled with Secure Boot off | the Secure Boot choice (no default outside Setup Mode: Enter alone re-prompts), the typed `no secure boot`, then the key file at the protection step and first boot; after a kill, the next boot is `protection=reduced (Secure Boot off)` without asking either again |
| `console.TestTheScreenAloneShowsTheChoiceThenTheSetupInfo` | no serial port, VGA, keys enrolled with Secure Boot off, no swtpm (a VMware VM) | the banner and the Secure Boot choice on the screen, `no secure boot` typed on its keyboard, then Enter at the protection step (key file); then first boot owns the screen and asks nothing: read off the screen in the large font, the :8443 address on QEMU's DHCP lease, a setup code of the form `XXXX-XXXX-XXXX-XXXX` and `Protection REDUCED` |
| `k0s.TestTheProductBundleBringsK0sAndTheHelloStack` | no swtpm, Secure Boot off with keys, 4 GiB, the lab hook's marker on the ESP, 22, 8443, 443 and 80 forwarded, the lab product bundle (`SNEAKERS_PRODUCT`) | the whole first boot (as `setup`); in normal operation no k0s runs and 443 doesn't answer; the bundle is uploaded, staged and applied through the Updates API; k0s starts from it, the node, the hello pod and the edge are Ready, `https://<box>/` answers `hello from sneakers-appliance`, 80 redirects to https, SSH and :8443 answer, `GetUpgrades` shows the product running, and k0s doesn't crash-loop ([k0s.md](k0s.md)) |
| `k0s.TestBlueTakesRedFromUpdatesAndRevertsToBlue` | no swtpm, Secure Boot off with keys, 22 and 8443 forwarded; two lab builds of one commit, BLUE (`SNEAKERS_IMAGE`, `SNEAKERS_BLUE_VERSION`) and a newer RED as its update `.bin` (`SNEAKERS_RED`, `SNEAKERS_RED_VERSION`), signed with the same lab keys | the whole first boot on BLUE; RED is uploaded and staged as a base update (its ESP entry with 3 tries), applied, and boots in the normal phase with its version on the console; once it's up, RED's entry loses its boot counter (marked good, [upgrades.md](upgrades.md)); a revert marks RED bad and BLUE boots again in the normal phase. The ESP is read with `mdir`. The image workflow builds one lab release, so there it skips; run it by hand on a BLUE and RED pair |
| `setup.TestFirstBootToAWorkingAppliance` | VGA and no serial port, keys enrolled with Secure Boot off, no swtpm, QEMU's user network with 22 and 8443 forwarded (a VMware VM) | the whole first boot: the console asks nothing after the boot's own choices and shows the :8443 address on the DHCP lease and the setup code, read off the screen; on :8443 the code makes the first admin with a password and TOTP, sshd answers only once the admin exists, the box issues an SSH key, a recovery key is set, the single admin is confirmed and one sign-in finishes setup; the console completes it and restarts by itself; after the restart the status screen shows the admin page, SSH takes the issued certificate and a TOTP code, `status` says `normal`, and :8443 serves with the certificate `status` names |
| `console.TestTheSerialLineAloneShowsTheChoiceAndTakesTheAnswer` | no display adapter, as above otherwise (a headless box) | the same on the serial line |
| `console.TestBothConsolesShowTheChoiceAndTheScreenCanAnswer` | serial and VGA | the choice on both; the answer typed on the screen's keyboard is taken while the serial line shows it |
| `reset.TestAResetFinishesAtBootThenFirstBootIsFresh` | Secure Boot enforcing, swtpm; the disk laid out as after first boot, with a begun reset record on the ESP | `phase=reset` finishes the reset and reboots without starting services; the key file, state and backup are out of the GPT and the record is `done`; the next boot is first boot (the protection step again), with no reset |
| `custody.TestKeyFileCustodyWithoutSecureBootOrTPM` | firmware without Secure Boot, no swtpm (the first lab target) | first boot keeps the key in the key file, formats and mounts the state, accessd is ready and nothing crash-loops; the next boot reads the mode back from the LUKS2 header and asks nothing; with the key file wiped, the boot stops at "State locked" with `KEYCUSTODY_LOCKED` and starts no service |
| `network.TestFirstBootGetsADHCPAddressAndKeepsSSHClosed` | no display adapter, keys enrolled with Secure Boot off, no swtpm; host port forwarded to the guest's 22 | netd takes QEMU's DHCP lease with no setting made (its `management addresses` line on the console), SSH gives no banner before the first-boot SSH step, and nothing crash-loops |


Once first boot owns the consoles, the services' own lines go to `/run/sneakers/console.log`
instead of the serial line, so the suite's crash-loop check (`Stable`) sees only what's printed
before first boot starts and its own restarts.

The screen is read from QEMU's screendump in whichever of the kernel's built-in fonts reads it
best: the large Terminus 16x32 the UKI selects, or the 8x16 the firmware and a small screen use.
Both are read out of the kernel under test, so there's no copy of a font in this repo.

Not in the suite yet: an elevation through the real sshd (request, approval, certificate login, the
time box, revocation).
