#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh: lay out the declared root tree (spec 1 Section 3.4, spec 2
# Section 3), pack it as an uncompressed SquashFS and append its dm-verity
# tree.
# Reproducible: the tree's modes are set explicitly, every file is root's,
# file times come from SOURCE_DATE_EPOCH, and the verity salt and UUID are
# fixed from the version. build/root/tree.txt is the declared tree;
# build/root/build_test.sh checks a build against it.
#
# The base root carries no k0s and no images: they ship in the product
# bundle (build/product/build.sh, docs/k0s.md). K0S or IMAGES set is
# refused, so an old caller can't put them back.
#
# Inputs (environment):
#   VERSION        the release version
#   ARCH           amd64 (default) or arm64
#   RELEASE        release.yaml the root is built for
#   OPENSSH        directory with the static sshd, sshd-session, sshd-auth and
#                  ssh-keygen (build/openssh/build.sh)
#   BUSYBOX        the static busybox (build/busybox/build.sh)
#   STATIC         directory with cryptsetup-<arch>, veritysetup-<arch>,
#                  mke2fs-<arch>, sgdisk-<arch> and their stamps
#                  (build/static); first boot can't make the state volumes
#                  without them
#   SERVICES       the service table (default os/rootfs/services.d)
#   OSADMIN_ASSETS the :8443 static pages (sneakers-web apps/appliance-admin;
#                  optional, the directory stays empty without them)
#   PINS_LDFLAGS   -X flags with the release pins, for the binaries that
#                  read them (init, accessd)
#   LAB_OVERLAY    lab builds only (the pins say channel lab): a directory
#                  whose files are added to the tree (build/lab/build.sh's
#                  test hook and throwaway stacks); it may not replace any
#                  file the tree already has
#   OUT            output directory: root-<version>.img and verity.json
#
# Every prebuilt input (OpenSSH, busybox and the static tools) must carry
# the stamp its build script writes for the current pins and config
# (build/lib/stamp.sh); a stale or unstamped one is refused, and each
# input's SHA-256 is logged. Before it packs the tree, every program the
# code and the service tables run must be in it (build/tools/rootexecs).
set -euo pipefail
umask 022

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${VERSION:?}" "${RELEASE:?}" "${OPENSSH:?}" "${BUSYBOX:?}" "${STATIC:?set STATIC to the static tools (build/static)}" "${OUT:?}"
if [ -n "${K0S:-}" ] || [ -n "${IMAGES:-}" ]; then
  echo "root: k0s and the images ship in the product bundle (build/product/build.sh), not the base root" >&2
  exit 1
fi
arch="${ARCH:-amd64}"
services="${SERVICES:-$root/os/rootfs/services.d}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH

for b in sshd sshd-session sshd-auth ssh-keygen; do
  [ -f "$OPENSSH/$b" ] || { echo "root: $OPENSSH/$b is missing (build/openssh/build.sh)" >&2; exit 1; }
done
[ -f "$BUSYBOX" ] || { echo "root: $BUSYBOX is missing (build/busybox/build.sh)" >&2; exit 1; }
for b in cryptsetup veritysetup mke2fs sgdisk; do
  [ -f "$STATIC/$b-$arch" ] || { echo "root: $STATIC/$b-$arch is missing (build/static)" >&2; exit 1; }
done
# shellcheck source=build/lib/stamp.sh
source "$root/build/lib/stamp.sh"
stamp_check "$(dirname "$BUSYBOX")/busybox.stamp" "$(busybox_stamp)" busybox || exit 1
stamp_check "$OPENSSH/openssh.stamp" "$(openssh_stamp)" OpenSSH || exit 1
for t in cryptsetup e2fsprogs gptfdisk; do
  stamp_check "$STATIC/$t-$arch.stamp" "$(static_stamp "$t" "$arch")" "static $t" || exit 1
done
for f in "$RELEASE" "$BUSYBOX" "$OPENSSH"/{sshd,sshd-session,sshd-auth,ssh-keygen} "$STATIC"/{cryptsetup,veritysetup,mke2fs,sgdisk}-"$arch"; do
  echo "root: input $f sha256 $(sha256sum "$f" | cut -d' ' -f1)"
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tree="$work/tree"
mkdir -p "$tree"/{bin,sbin,etc/k0s/containerd.d,usr/bin,usr/sbin,usr/libexec/openssh,usr/libexec/sneakers,usr/lib/sneakers/services.d} \
  "$tree"/usr/share/sneakers/{charts,release,osadmin} "$tree"/{proc,sys,dev,run,tmp,var/lib,boot/efi} \
  "$tree"/lib/modules "$tree"/usr/libexec/k0s/kubelet-plugins/volume/exec

echo "root: Go binaries ($arch)"
gobuild() { # out package
  GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w ${PINS_LDFLAGS:-}" -o "$1" "$root/cmd/$2"
}
gobuild "$tree/sbin/init" sneakers-init
for c in sneakers-accessd sneakers-console sneakers-edgefall sneakers-firstboot sneakers-netd sneakers-osadmin sneakers-shell sneakers-sshd-run; do
  gobuild "$tree/usr/bin/$c" "$c"
done
# accessd runs the root shell through it, so it and every directory above it
# are root's and not writable by others.
for c in sneakers-elevated; do
  gobuild "$tree/usr/libexec/$c" "$c"
done

echo "root: OpenSSH, busybox"
install -m 0755 "$OPENSSH/sshd" "$tree/usr/sbin/sshd"
install -m 0755 "$OPENSSH/sshd-session" "$OPENSSH/sshd-auth" "$tree/usr/libexec/openssh/"
install -m 0755 "$OPENSSH/ssh-keygen" "$tree/usr/bin/ssh-keygen"
# The elevated session's /bin/sh. Its applets run without links
# (FEATURE_SH_STANDALONE).
install -m 0755 "$BUSYBOX" "$tree/bin/busybox"
ln -s busybox "$tree/bin/sh"
install -m 0755 "$STATIC/cryptsetup-$arch" "$tree/usr/sbin/cryptsetup"
install -m 0755 "$STATIC/veritysetup-$arch" "$tree/usr/sbin/veritysetup"
install -m 0755 "$STATIC/mke2fs-$arch" "$tree/usr/sbin/mkfs.ext4"
install -m 0755 "$STATIC/sgdisk-$arch" "$tree/usr/sbin/sgdisk"

# What the base OS gives k0s, which itself comes with the product bundle
# (docs/k0s.md): its config template, containerd's config (k0s would
# write one into the read-only /etc otherwise), the interim launcher,
# and the host paths its pods mount: /etc/cni and /opt lead to the state
# volume, and /lib/modules stays empty (no loadable modules).
install -m 0644 "$root/os/k0s/k0s.yaml.tmpl" "$tree/etc/k0s/k0s.yaml.tmpl"
install -m 0644 "$root/os/k0s/containerd.toml" "$tree/etc/k0s/containerd.toml"
install -m 0755 "$root/os/k0s/k0s-interim" "$tree/usr/libexec/sneakers/k0s-interim"
ln -s /var/lib/cni-conf "$tree/etc/cni"
ln -s /var/lib/opt "$tree/opt"
# containerd puts its NRI socket in /var/run, and the kubelet and containerd
# write pod logs to /var/log/pods; /var itself is the read-only root.
ln -s /run "$tree/var/run"
ln -s /var/lib/log "$tree/var/log"
# The kubelet mounts tmpfs volumes with mount(8), and reads the machine ID
# (made once per box, on the state volume, by k0s-interim).
ln -s busybox "$tree/bin/mount"
ln -s busybox "$tree/bin/umount"
ln -s /var/lib/sneakers/machine-id "$tree/etc/machine-id"
# The root shell's kubectl and helm follow the installed product's current
# slot (they dangle until one is installed); k0s answers as kubectl when
# it's run by that name.
ln -s /var/lib/sneakers/product/current/k0s "$tree/usr/bin/kubectl"
ln -s /var/lib/sneakers/product/current/helm "$tree/usr/bin/helm"

echo "root: release, service table"
install -m 0644 "$RELEASE" "$tree/usr/share/sneakers/release/release.yaml"
shopt -s nullglob
svc=("$services"/*.yaml)
shopt -u nullglob
[ "${#svc[@]}" -gt 0 ] || { echo "root: no service table in $services" >&2; exit 1; }
install -m 0644 "${svc[@]}" "$tree/usr/lib/sneakers/services.d/"
if [ -n "${OSADMIN_ASSETS:-}" ]; then
  cp -r "$OSADMIN_ASSETS/." "$tree/usr/share/sneakers/osadmin/"
  find "$tree/usr/share/sneakers/osadmin" -type d -exec chmod 0755 {} + -o -type f -exec chmod 0644 {} +
fi

if [ -n "${LAB_OVERLAY:-}" ]; then
  case " ${PINS_LDFLAGS:-} " in
    *".Channel=lab "*) ;;
    *) echo "root: LAB_OVERLAY is for lab builds only (the pins don't say channel lab)" >&2; exit 1 ;;
  esac
  while IFS= read -r -d '' f; do
    rel="${f#"$LAB_OVERLAY"/}"
    [ ! -e "$tree/$rel" ] || { echo "root: LAB_OVERLAY would replace /$rel" >&2; exit 1; }
    mkdir -p "$(dirname "$tree/$rel")"
    if [ -x "$f" ]; then install -m 0755 "$f" "$tree/$rel"; else install -m 0644 "$f" "$tree/$rel"; fi
  done < <(find "$LAB_OVERLAY" -type f -print0 | sort -z)
  echo "root: lab overlay from $LAB_OVERLAY"
fi

# Every program the code and the service tables run is in the tree.
go run "$root/build/tools/rootexecs" --src "$root" --tree "$tree" --services "$tree/usr/lib/sneakers/services.d"

# /etc is read-only: the account files and the resolver config live in /run.
cp -P "$root"/os/rootfs/etc/{passwd,group,shadow} "$tree/etc/"
ln -s /run/sneakers/resolv.conf "$tree/etc/resolv.conf"
# k0s and the kubelet resolve localhost; there's no resolver for it otherwise.
printf '127.0.0.1\tlocalhost\n::1\tlocalhost\n' > "$tree/etc/hosts"
chmod 0644 "$tree/etc/hosts"
if find "$tree" -perm /6000 | grep -q .; then
  echo "root: a setuid or setgid file in the tree:" >&2
  find "$tree" -perm /6000 >&2
  exit 1
fi
find "$tree" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkdir -p "$OUT"
img="$OUT/root-$VERSION.img"
rm -f "$img"
# mksquashfs takes its timestamps from SOURCE_DATE_EPOCH.
# Uncompressed (inodes, ids, data, fragments, xattrs): SquashFS compresses each
# block on its own, so a delta between two compressed roots saves little; the
# .bin payload carries the root as it is, and a patch carries a zstd delta.
mksquashfs "$tree" "$img" -comp zstd -noI -noId -noD -noF -noX -all-root -no-xattrs -noappend -quiet
size="$(stat -c %s "$img")"
pad=$(( (4096 - size % 4096) % 4096 ))
[ "$pad" -eq 0 ] || head -c "$pad" /dev/zero >> "$img"
offset="$(stat -c %s "$img")"
salt="$(printf 'sneakers root %s' "$VERSION" | sha256sum | cut -d' ' -f1)"
uuid="$(python3 -c 'import hashlib,sys,uuid; print(uuid.UUID(bytes=hashlib.sha256(("sneakers uuid "+sys.argv[1]).encode()).digest()[:16], version=4))' "$VERSION")"
fmt="$(veritysetup format --hash-offset="$offset" --salt="$salt" --uuid="$uuid" "$img" "$img")"
roothash="$(printf '%s\n' "$fmt" | sed -n 's/^Root hash:[[:space:]]*//p')"
[[ "$roothash" =~ ^[0-9a-f]{64}$ ]] || { echo "root: no root hash from veritysetup" >&2; printf '%s\n' "$fmt" >&2; exit 1; }
printf '{"roothash":"%s","hashOffset":%d}\n' "$roothash" "$offset" > "$OUT/verity.json"
echo "root: wrote $img ($(stat -c %s "$img") bytes, data $offset), root hash $roothash"
