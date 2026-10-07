#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh: lay out the declared root tree (spec 1 Section 3.4, spec 2
# Section 3), pack it as SquashFS (zstd) and append its dm-verity tree.
# Reproducible: the tree's modes are set explicitly, every file is root's,
# file times come from SOURCE_DATE_EPOCH, and the verity salt and UUID are
# fixed from the version. build/root/tree.txt is the declared tree;
# build/root/build_test.sh checks a build against it.
#
# Inputs (environment):
#   VERSION        the release version
#   ARCH           amd64 (default) or arm64
#   RELEASE        release.yaml the root is built for (its k0s pin is checked)
#   K0S            the k0s binary
#   OPENSSH        directory with the static sshd, sshd-session, sshd-auth and
#                  ssh-keygen (build/openssh/build.sh)
#   BUSYBOX        the static busybox (build/busybox/build.sh)
#   IMAGES         the airgap bundle directory (build/bundle/build.sh); may
#                  be unset when release.yaml pins no images
#   STATIC         directory with cryptsetup-<arch>, veritysetup-<arch>,
#                  mke2fs-<arch>, sgdisk-<arch> (optional)
#   SERVICES       the service table (default os/rootfs/services.d)
#   OSADMIN_ASSETS the :8443 static pages (sneakers-web apps/appliance-admin;
#                  optional, the directory stays empty without them)
#   PINS_LDFLAGS   -X flags with the release pins, for the binaries that
#                  read them (init, accessd)
#   OUT            output directory: root-<version>.img and verity.json
set -euo pipefail
umask 022

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${VERSION:?}" "${RELEASE:?}" "${K0S:?}" "${OPENSSH:?}" "${BUSYBOX:?}" "${OUT:?}"
arch="${ARCH:-amd64}"
services="${SERVICES:-$root/os/rootfs/services.d}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH

want_k0s="$(go run "$root/build/tools/k0spin" "$RELEASE" "$arch")"
got_k0s="$(sha256sum "$K0S" | cut -d' ' -f1)"
[ "$want_k0s" = "$got_k0s" ] || { echo "root: $K0S has SHA-256 $got_k0s; release.yaml pins $want_k0s" >&2; exit 1; }
for b in sshd sshd-session sshd-auth ssh-keygen; do
  [ -f "$OPENSSH/$b" ] || { echo "root: $OPENSSH/$b is missing (build/openssh/build.sh)" >&2; exit 1; }
done
[ -f "$BUSYBOX" ] || { echo "root: $BUSYBOX is missing (build/busybox/build.sh)" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tree="$work/tree"
mkdir -p "$tree"/{bin,sbin,etc/k0s,usr/bin,usr/sbin,usr/libexec/openssh,usr/lib/sneakers/services.d} \
  "$tree"/usr/share/sneakers/{images,charts,release,osadmin} "$tree"/{proc,sys,dev,run,tmp,var/lib,boot/efi}

echo "root: Go binaries ($arch)"
gobuild() { # out package
  GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w ${PINS_LDFLAGS:-}" -o "$1" "$root/cmd/$2"
}
gobuild "$tree/sbin/init" sneakers-init
for c in sneakers-accessd sneakers-osadmin sneakers-shell; do
  gobuild "$tree/usr/bin/$c" "$c"
done
# sshd runs these as forced commands and as the AuthorizedKeysCommand, so
# they and every directory above them are root's and not writable by others.
for c in sneakers-elevated sneakers-enrol sneakers-enrol-keys; do
  gobuild "$tree/usr/libexec/$c" "$c"
done

echo "root: k0s, OpenSSH, busybox"
install -m 0755 "$K0S" "$tree/usr/bin/k0s"
install -m 0755 "$OPENSSH/sshd" "$tree/usr/sbin/sshd"
install -m 0755 "$OPENSSH/sshd-session" "$OPENSSH/sshd-auth" "$tree/usr/libexec/openssh/"
install -m 0755 "$OPENSSH/ssh-keygen" "$tree/usr/bin/ssh-keygen"
# The elevated session's /bin/sh. Its applets run without links
# (FEATURE_SH_STANDALONE).
install -m 0755 "$BUSYBOX" "$tree/bin/busybox"
ln -s busybox "$tree/bin/sh"
if [ -n "${STATIC:-}" ]; then
  install -m 0755 "$STATIC/cryptsetup-$arch" "$tree/usr/sbin/cryptsetup"
  install -m 0755 "$STATIC/veritysetup-$arch" "$tree/usr/sbin/veritysetup"
  install -m 0755 "$STATIC/mke2fs-$arch" "$tree/usr/sbin/mkfs.ext4"
  install -m 0755 "$STATIC/sgdisk-$arch" "$tree/usr/sbin/sgdisk"
fi

echo "root: release, bundle, service table"
install -m 0644 "$RELEASE" "$tree/usr/share/sneakers/release/release.yaml"
if [ -n "${IMAGES:-}" ]; then
  [ -d "$IMAGES" ] || { echo "root: the bundle $IMAGES isn't a directory" >&2; exit 1; }
  find "$IMAGES" -mindepth 1 -maxdepth 1 -type f -exec install -m 0644 {} "$tree/usr/share/sneakers/images/" \;
fi
shopt -s nullglob
svc=("$services"/*.yaml)
shopt -u nullglob
[ "${#svc[@]}" -gt 0 ] || { echo "root: no service table in $services" >&2; exit 1; }
install -m 0644 "${svc[@]}" "$tree/usr/lib/sneakers/services.d/"
if [ -n "${OSADMIN_ASSETS:-}" ]; then
  cp -r "$OSADMIN_ASSETS/." "$tree/usr/share/sneakers/osadmin/"
  find "$tree/usr/share/sneakers/osadmin" -type d -exec chmod 0755 {} + -o -type f -exec chmod 0644 {} +
fi

# /etc is read-only: the account files and the resolver config live in /run.
cp -P "$root"/os/rootfs/etc/{passwd,group,shadow} "$tree/etc/"
ln -s /run/sneakers/resolv.conf "$tree/etc/resolv.conf"
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
mksquashfs "$tree" "$img" -comp zstd -all-root -no-xattrs -noappend -quiet
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
