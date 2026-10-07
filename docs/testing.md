# Testing

| What | Where | When |
|---|---|---|
| Unit tests (the chain, the writers, init, custody, Secure Boot, the upgrade stager) | `go test ./...` | every PR (`🧪 Build & Test`) |
| Tool interop (efitools, cosign, sbsign, sbverify, unsquashfs, ukify against the kit's checks) | `go test -tags tools ./test/kit/labkeys/` | every PR (`🔑 Lab keys and tool interop`) |
| The root image: reproducible, the declared tree, its refusals | `bash build/root/build_test.sh` | every PR (`🔑 Lab keys and tool interop`) |
| The airgap bundle: pull by digest per architecture, signatures, both-way check (a `registry:2` container) | `go test ./internal/bundle/` | every PR (`🧪 Build & Test`) |
| Kernel and static tools | `job-image-build.yaml` | PRs that touch their inputs |
| The image suite (QEMU, OVMF Secure Boot, swtpm) | `go test -tags image ./test/image/...` | every PR (`image-e2e.yml`) |

Tests that need a tool skip with its name when it's missing; CI sets `SNEAKERS_REQUIRE_TOOLS=1`, so
there a missing tool fails instead.

## The lab release

`build/lab/build.sh` builds a whole release the way the release workflow does, signed with a key
set `build/keys/lab-keys.sh` makes for that run only: the (empty) airgap bundle
(`build/bundle/build.sh`), the root image (`build/root/build.sh`, with the static OpenSSH and
busybox), the
UKI (`build/uki/assemble.sh`, signed with `sbsign`), systemd-boot (signed), the enrolment
material, `release.yaml` and the artifact (`sneakers-artifact assemble`, then `cosign sign-blob`
over the index blob and `sneakers-artifact attach`). It then builds a kit pinned to that run's keys
and writes the raw disk with it, so every PR runs the kit's whole chain against a real release. In
CI the keys live on a tmpfs that's unmounted at the end of the job; nothing built is uploaded.

## The QEMU harness

`test/image/harness` boots a disk on q35 with SMM and OVMF's Secure Boot build and a vars store in
one of three states (`virt-fw-vars`): the run's lab PK, KEK and db enrolled and enforcing
(`Enrolled`), empty for Setup Mode (`Off`), or the keys enrolled with `SecureBootEnable` off
(`OffWithKeys`, a VMware VM with Secure Boot off). It adds swtpm as the TPM when asked and uses KVM
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
the entry goes when its cause is fixed. Today that's accessd: init doesn't mount the state volume
yet.

## The image suite

| Test | What it boots | What it checks |
|---|---|---|
| `harness.TestHarnessBootsToSerialBanner` | Secure Boot enforcing (lab keys), swtpm | `phase=firstboot` |
| `harness.TestFirstBootStaysUp` | as above | init keeps running past the banner and reaches the service table; no crash loop except the known one |
| `reduced.TestNoSecureBootNoTPMBootsReduced` | no swtpm; an empty vars store, and keys enrolled with Secure Boot off | the Secure Boot choice (no default outside Setup Mode: Enter alone re-prompts), the typed `no secure boot`, first boot; after a kill, the next boot is `protection=reduced (Secure Boot off)` without asking |
| `console.TestTheScreenAloneShowsTheChoiceAndTakesTheAnswer` | no serial port, VGA, keys enrolled with Secure Boot off, no swtpm (a VMware VM) | the banner and the Secure Boot choice on the screen, `no secure boot` typed on its keyboard, first boot |
| `console.TestTheSerialLineAloneShowsTheChoiceAndTakesTheAnswer` | no display adapter, as above otherwise (a headless box) | the same on the serial line |
| `console.TestBothConsolesShowTheChoiceAndTheScreenCanAnswer` | serial and VGA | the choice on both; the answer typed on the screen's keyboard is taken while the serial line shows it |
| `reset.TestAResetFinishesAtBootThenFirstBootIsFresh` | Secure Boot enforcing, swtpm; the disk laid out as after first boot, with a begun reset record on the ESP | `phase=reset` finishes the reset and reboots without starting services; the key file, state and backup are out of the GPT and the record is `done`; the next boot is first boot, with no reset |

Not in the suite yet, because the image can't do it: an elevation through the real sshd (request,
approval, certificate login, the time box, revocation) and the SSH key enrolment window. Both need
the state volume mounted for accessd, an sshd service, a guest address and the console's approval
on access.sock.
