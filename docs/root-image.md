# The root image and the airgap bundle

The root is a read-only SquashFS (zstd) built from a declared tree, never from a distro install,
with its dm-verity hash tree appended. It's the small base image: the OS, the console, the :8443
admin, and the access, network and SSH services, about 64 MB with its verity tree. k0s and every
image ship in the product bundle instead ([release.md](release.md#the-product-bundle)), so the
root holds neither, and the kit refuses a root that does. The verity root hash and offset go into the UKI's command
line, and the UKI is signed, so the root is signed transitively.

## The declared tree

`build/root/tree.txt` is the whole tree, with each entry's mode and owner. Every entry is root's
(`0/0`), nothing is setuid or setgid, programs are `0755`, data files `0644`. Services that run
unprivileged (`osadmin`) get their user from the service table (`user:`), never from the file's
owner.

| Path | What |
|---|---|
| `/sbin/init` | `sneakers-init` |
| `/usr/bin/sneakers-accessd`, `/usr/bin/sneakers-osadmin` | the access service and the :8443 front (services) |
| `/usr/bin/sneakers-firstboot`, `/usr/bin/sneakers-console` | the setup wizard and the normal-phase console, which own the console in turn ([console.md](console.md)) |
| `/usr/bin/sneakers-shell` | every admin's login shell and sshd's `ForceCommand` |
| `/usr/libexec/sneakers-elevated` | the root shell, started by accessd for an opened challenge; root's |
| `/usr/sbin/sshd`, `/usr/libexec/openssh/{sshd-session,sshd-auth}`, `/usr/bin/ssh-keygen` | static OpenSSH ([static-tools.md](static-tools.md)) |
| `/bin/busybox`, `/bin/sh -> busybox` | the elevated session's shell (`ASH_EXPAND_PRMT` for the minutes-left prompt) |
| `/etc/k0s/{k0s.yaml.tmpl,containerd.toml,containerd.d/}`, `/usr/libexec/sneakers/k0s-interim` | k0s's config, containerd's config and the interim script that prepares the box and starts k0s from the installed product bundle ([k0s.md](k0s.md)) |
| `/etc/cni -> /var/lib/cni-conf`, `/opt -> /var/lib/opt`, `/var/run -> /run`, `/var/log -> /var/lib/log`, `/etc/machine-id`, `/etc/hosts`, `/bin/{mount,umount}`, `/lib/modules`, `/usr/libexec/k0s/kubelet-plugins/volume/exec` | what k0s, containerd and the kubelet expect on the host ([k0s.md](k0s.md)) |
| `/usr/lib/sneakers/services.d/` | the service table, from `os/rootfs/services.d/` |
| `/usr/share/sneakers/release/release.yaml` | the release the root was built for |
| `/usr/share/sneakers/osadmin/` | the :8443 static pages (`OSADMIN_ASSETS`; empty until sneakers-web ships them) |
| `/etc/{passwd,group,shadow}` | links into `/run/sneakers/accounts/`, which accessd renders |
| `/etc/resolv.conf` | a link to `/run/sneakers/resolv.conf` |
| `/usr/sbin/{cryptsetup,veritysetup,mkfs.ext4,sgdisk}` | the static tools, when `STATIC` is given |

`build/root/build.sh` takes its inputs from the environment (the header lists them): the version,
the architecture, `release.yaml`, the OpenSSH directory, busybox and the release pins
(`PINS_LDFLAGS`, linked into init and accessd). It refuses `K0S` or `IMAGES` (they belong to the
product bundle), a missing OpenSSH or busybox, an empty service table, and any
setuid or setgid file. `LAB_OVERLAY` (lab builds only; refused unless the pins say channel `lab`)
adds the files of a directory to the tree and is refused if it would replace one.

## Reproducible

The same inputs and `SOURCE_DATE_EPOCH` give the same bytes: the modes are set explicitly (umask
`022`), `mksquashfs -all-root` makes every file root's, file times come from `SOURCE_DATE_EPOCH`,
and the verity salt and UUID are derived from the version. The Go binaries are built with
`-trimpath`.

`build/root/build_test.sh` builds twice and compares the images and `verity.json` byte for byte,
checks the image's listing (`unsquashfs -lln`) against `tree.txt`, and checks the refusals. It runs
on every PR in `🔑 Lab keys and tool interop`. After a deliberate change to the tree, `UPDATE=1
bash build/root/build_test.sh` rewrites `tree.txt`; review the diff.

The image suite's job summary reports the lab root image's size, and the lab product bundle's, on
every PR.

## The airgap bundle

`build/bundle/build.sh` (the `build/tools/bundle` tool) builds the product bundle's `images/`
directory ([release.md](release.md#the-product-bundle)) from `release.yaml`, for one architecture:

1. Every image `release.yaml` pins (`services`, `thirdParty`, `platform` and
   `kubernetes.k0s.images`; not the helm test `tools`) must be pinned by a `sha256:` digest.
2. The org release-key signature of each pinned digest is read from `SIGNATURES`
   (`<hex>.sigstore.json`) and checked first. A missing or foreign signature is
   `KIT_IMAGE_UNSIGNED`.
3. The image is pulled by digest. From a multi-arch index only that architecture's manifest, config
   and layers are pulled, and the index itself is kept, so the pinned digest stays the archive's
   root (as `ctr images export --platform` does).
4. Each image is written as an OCI archive, `<hex>.tar`, with entries in name order, root's, and
   stamped with `SOURCE_DATE_EPOCH`, so the same image gives the same bytes. The signature goes
   beside it as `<hex>.tar.sigstore.json`.
5. The finished directory is checked against `release.yaml` both ways: an image it pins that's
   missing, or anything it doesn't pin, is `KIT_BUNDLE_MISMATCH`. The box runs the same check on
   every product bundle it unpacks, before it uses it.

Any refusal leaves the output directory empty. The lab release pins k0s's own images, the hello
image and the interim edge's Traefik (`build/lab/images.txt`), and the lab build signs each digest with that run's key: it
fetches the manifest or index bytes with `bundle manifest` and signs them with `cosign sign-blob`.

### Not pinnable yet

The production bundle can't be built yet, and the build refuses clearly:

- sneakers-release's `manifest/release.yaml` pins every Sneakers service at `sha256:TBD-at-release`
  (`KIT_BUNDLE_MISMATCH`, "not a sha256 digest").
- sneakers-release publishes no org countersignatures of the images yet. `build/release/build.sh`
  refuses without `SIGNATURES`.
- The release doesn't list Traefik, cert-manager, the maintenance app or k0s's own system images
  yet, and its digests aren't multi-arch indexes yet (spec 1, Section 3.4).
