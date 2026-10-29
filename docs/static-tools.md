# Static OpenSSH and busybox

The root image carries a static OpenSSH for key-only SSH and a static busybox for the elevation
shell. Both are built from pinned sources in `build/openssh/versions.env`, each tarball checked
against its SHA-256 before it is unpacked, inside a musl builder pinned by digest.

| Output | Built by | What |
|---|---|---|
| `sshd`, `sshd-session`, `sshd-auth` | `build/openssh/build.sh` | OpenSSH portable with a pinned OpenSSL's libcrypto; no zlib, PAM, Kerberos or login records |
| `ssh-keygen` | `build/openssh/build.sh` | for the revocation list (`ssh-keygen -k -u`) |
| `busybox` | `build/busybox/build.sh` | `sh` (ash) and the support tools in `build/busybox/busybox.config`; every network daemon off |

OpenSSH is configured with the appliance paths: `sshd-session` and `sshd-auth` in
`/usr/libexec/openssh`, the privilege-separation directory `/run/sneakers/sshd-empty` (on /run, so
accessd and `sneakers-sshd-run` make it, root's and 0755, before they run `sshd -t` or sshd) and the
config under `/run/sneakers/ssh`. `sshd-session` arms its login grace time with `setitimer`, which
needs the kernel's POSIX timers (`CONFIG_POSIX_TIMERS`, in `os/kernel/required.txt`). busybox runs its applets from the shell without symlinks, so the
root image needs only the one binary.

Only the options `busybox.config` turns on are built, and busybox refuses any other with
`unrecognized option` (there is no `readlink -f`, for one; resolve a link with `cd -P` and `pwd`).
`os/k0s/busybox_test.go` reads every shell script under `os/` and the lab overlay and fails when one
uses an applet option the config doesn't build. Turning an option on means a rebuilt busybox; prefer
the shell's own builtins.

```sh
bash build/busybox/build.sh out/static
bash build/openssh/build.sh out/static
bash build/openssh/test.sh out/static
```

The scripts need Docker and build for the host's architecture. CI (`job-static-tools.yaml`) builds
amd64 and arm64 on native runners, caches the outputs by the hash of `build/openssh/` and
`build/busybox/`, and lists each binary's SHA-256 in the job summary. It then runs the
`internal/sshconfig` tests with the built `sshd`, so every rendered `sshd_config` passes `sshd -t`
(see [ssh-and-elevation.md](ssh-and-elevation.md)).

To bump a version, change it and its SHA-256 in `versions.env`. For OpenSSH, check the tarball's
signature against the OpenSSH release key before taking its SHA-256.

## The QEMU guest agent

The amd64 root also carries a static `qemu-ga` (spec 1 Section 2.8), so Proxmox VE and other KVM
hosts can read the box's addresses, freeze its file systems for a backup and shut it down cleanly.
`build/static/qemu-ga.sh amd64` builds only the agent (`--without-default-features
--enable-guest-agent`, no emulator or tools) from the QEMU release tarball `QEMU_VERSION` names in
`build/ci/versions.env`, checked against `QEMU_SHA256`, in the pinned Alpine container, with meson
from QEMU's own bundled wheels (nothing comes from PyPI). It writes `build/out/qemu-ga-amd64` and
`qemu-ga-amd64.rpcs`, the RPCs that build has, and fails if the service table allows one it
doesn't. To bump QEMU, check the new tarball's signature against the QEMU release key first, then
take its SHA-256.

The `qemu-ga` service (`os/rootfs/services.d/qemu-ga.yaml`) runs it as root in first boot and
normal operation, once init has linked `/dev/virtio-ports/org.qemu.guest_agent.0`
([init.md](init.md)), with `--allow-rpcs` naming the only RPCs that answer: `guest-sync`,
`guest-sync-delimited`, `guest-ping`, `guest-info`, `guest-shutdown`, `guest-get-osinfo`,
`guest-get-host-name`, `guest-network-get-interfaces` and the four `guest-fsfreeze-*`. Everything
else is disabled, among them every command that runs programs, reads or writes files, or sets
passwords or SSH keys (`guest-exec`, `guest-file-*`, `guest-set-user-password`,
`guest-ssh-*`), so the hypervisor's operator gets no shell the closed shell doesn't give the
admin. `guest-shutdown` runs `/sbin/poweroff` (or `halt` or `reboot`), which is
`sneakers-hvpower`: it asks init over `power.sock` for the drained power-off or reboot the closed
shell gets, and init takes it only from that program running as root
([factory-reset.md](factory-reset.md)).

## Licences

| Component | Licence |
|---|---|
| OpenSSH portable | BSD-style (the OpenSSH licence) |
| OpenSSL | Apache-2.0 |
| busybox | GPL-2.0-only; the exact pinned source tarball is the corresponding source |
| qemu-ga (QEMU) | GPL-2.0, QEMU's licence, with Alpine's static glib (LGPL-2.1-or-later) and its permissively licensed dependencies linked in; the exact pinned QEMU tarball and the Alpine packages' sources are the corresponding source |
