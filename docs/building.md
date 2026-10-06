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
| UKI | `build/uki/assemble.sh` | `sneakers-<version>.efi` (unsigned) |

## The kernel

One kernel serves every amd64 platform, because one signed UKI does: `os/kernel/config-base` and
every profile (`vmware`, `qemu`, `proxmox`) are merged onto `tinyconfig`, with
`CONFIG_MODULES=n` (everything built in). The build fails if any requested option was dropped by
an unmet dependency, and `build/kernel/check-config.sh` checks the options the appliance can't run
without (`os/kernel/required.txt`: cgroup v2, namespaces, overlayfs, veth, bridge and
`br_netfilter`, nftables and the iptables compatibility layer, conntrack, seccomp, dm-verity,
dm-crypt, SquashFS with zstd, efivarfs, the TPM drivers, the lockdown LSM). Lockdown isn't forced
in the config; the UKI's command line sets `lockdown=integrity`.

Builds are reproducible from `SOURCE_DATE_EPOCH` (the last commit's time by default) with fixed
build user, host and version strings. The `Image Build` workflow builds the kernel and the static
tools when a pull request touches what they're built from, caches them by the hash of their inputs,
and records each digest in the job summary.

The static tools build inside Docker (pinned Alpine and Debian images), so a build host needs
Docker. Each script fails if its output has a dynamic loader.
