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

## Licences

| Component | Licence |
|---|---|
| OpenSSH portable | BSD-style (the OpenSSH licence) |
| OpenSSL | Apache-2.0 |
| busybox | GPL-2.0-only; the exact pinned source tarball is the corresponding source |
