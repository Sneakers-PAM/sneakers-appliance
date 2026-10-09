# Building the OS from source

Everything the image is built from is pinned in `build/ci/versions.env` and checked: the kernel by
its stable git tag and that tag's commit, cryptsetup by kernel.org's published SHA-256, the
builder containers by tag.

| Piece | Script | Output |
|---|---|---|
| Kernel (amd64) | `build/kernel/build.sh amd64` | `build/out/kernel/amd64/bzImage`, its `.config` and `kernelrelease` |
| cryptsetup, veritysetup (static, musl) | `build/static/cryptsetup.sh amd64` | `build/out/{cryptsetup,veritysetup}-amd64` |
| mke2fs (static) | `build/static/e2fsprogs.sh amd64` | `build/out/mke2fs-amd64` |
| sgdisk (static) | `build/static/gptfdisk.sh amd64` | `build/out/sgdisk-amd64` |
| OpenSSH, busybox (static, musl) | `build/openssh/build.sh`, `build/busybox/build.sh` | `out/static/{sshd,sshd-session,sshd-auth,ssh-keygen,busybox}` |
| Airgap bundle | `build/bundle/build.sh` | `<hex>.tar` and its signature per pinned image ([root-image.md](root-image.md)) |
| Root image | `build/root/build.sh` | `root-<version>.img` (SquashFS with the verity tree) and `verity.json` ([root-image.md](root-image.md)) |
| UKI | `build/uki/assemble.sh` | `sneakers-<version>.efi` (unsigned) |

## The kernel

One kernel serves every amd64 platform, because one signed UKI does: `os/kernel/config-base` and
every profile (`vmware`, `qemu`, `proxmox`) are merged onto `tinyconfig`, with
`CONFIG_MODULES=n` (everything built in). The build fails if any requested option was dropped by
an unmet dependency, and `build/kernel/check-config.sh` checks the options the appliance can't run
without (`os/kernel/required.txt`: cgroup v2, namespaces, overlayfs, veth, bridge and
`br_netfilter`, nftables and the iptables compatibility layer, conntrack, seccomp, dm-verity,
dm-crypt, SquashFS with zstd, efivarfs, the TPM drivers, the lockdown LSM, and the POSIX timers
sshd's login grace time needs, which `tinyconfig` turns off). Lockdown isn't forced
in the config; the UKI's command line sets `lockdown=integrity`.

Builds are reproducible from `SOURCE_DATE_EPOCH` (the last commit's time by default) with fixed
build user, host and version strings. The `Image Build` workflow builds the kernel and the static
tools when a pull request touches what they're built from, caches them by the hash of their inputs,
and records each digest in the job summary.

The static tools build inside Docker (pinned Alpine and Debian images), so a build host needs
Docker. Each script fails if its output has a dynamic loader.

## Prebuilt inputs

The root build takes OpenSSH, busybox and the static tools as prebuilt inputs, and all of them are
required (`STATIC` too: first boot can't make the state volumes without cryptsetup and
mkfs.ext4). Each build script writes a stamp next to its output (`busybox.stamp`,
`openssh.stamp`, `<cryptsetup|e2fsprogs|gptfdisk>-<arch>.stamp`): the tool, its pinned version and
the SHA-256 of everything that decides the build, the pins, the busybox config and the build script
itself (`build/lib/stamp.sh`). The root build works the same stamp out from the tree it runs in and
refuses an input whose stamp is missing or different ("stale or unstamped busybox: ... build it
again"), so a binary left from an older pin or config in a holding folder never ships. It logs
every input's SHA-256 (`root: input <file> sha256 <hex>`), so a build can be traced to exactly what
went in.

Before it packs the tree, the root build checks that every program the box runs is in it
(`build/tools/rootexecs`): each absolute `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` and `/usr/libexec`
path in `cmd/` and `internal/` (tests left out) and each `exec`, `pre-start` and leading `args`
path in the service tables, the lab overlay's included, must be an executable file in the tree,
through links. A missing one fails the build. A lab build's version carries its own stamp,
`r<UTC time>` (or `BUILD_STAMP`), before `g<commit>`, so two builds of one commit never share a
version.

The first boot of a fresh OVA is proved on the lab ESXi proof VM before it ships; the build itself
runs no VM.
