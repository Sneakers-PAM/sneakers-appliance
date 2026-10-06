#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh: lay out the root tree (spec 1 Section 3.4), pack it as SquashFS
# (zstd) and append its dm-verity tree. Reproducible: file times, owners and
# the verity salt and UUID are fixed from SOURCE_DATE_EPOCH and the version.
#
# Inputs (environment):
#   VERSION      the release version
#   ARCH         amd64 (default)
#   RELEASE      release.yaml the root is built for (its k0s pin is checked)
#   K0S          the k0s binary
#   IMAGES       directory of the airgap bundle (<hex>.tar and signatures); may be empty
#   STATIC       directory with cryptsetup-<arch>, veritysetup-<arch>, mke2fs-<arch>, sgdisk-<arch> (optional)
#   SERVICES     directory of services.d/*.yaml (optional)
#   OUT          output directory: root-<version>.img and verity.json
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${VERSION:?}" "${RELEASE:?}" "${K0S:?}" "${OUT:?}"
arch="${ARCH:-amd64}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH

want_k0s="$(go run "$root/build/tools/k0spin" "$RELEASE" "$arch")"
got_k0s="$(sha256sum "$K0S" | cut -d' ' -f1)"
[ "$want_k0s" = "$got_k0s" ] || { echo "root: $K0S has SHA-256 $got_k0s; release.yaml pins $want_k0s" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tree="$work/tree"
mkdir -p "$tree"/{sbin,usr/bin,usr/sbin,usr/lib/sneakers/services.d,usr/share/sneakers/{images,charts,release},etc/k0s,proc,sys,dev,run,tmp,var,boot/efi}
GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w ${INIT_LDFLAGS:-}" -o "$tree/sbin/init" "$root/cmd/sneakers-init"
install -m 0755 "$K0S" "$tree/usr/bin/k0s"
install -m 0644 "$RELEASE" "$tree/usr/share/sneakers/release/release.yaml"
if [ -n "${IMAGES:-}" ] && [ -d "$IMAGES" ]; then
  cp -a "$IMAGES/." "$tree/usr/share/sneakers/images/"
fi
if [ -n "${STATIC:-}" ]; then
  install -m 0755 "$STATIC/cryptsetup-$arch" "$tree/usr/sbin/cryptsetup"
  install -m 0755 "$STATIC/veritysetup-$arch" "$tree/usr/sbin/veritysetup"
  install -m 0755 "$STATIC/mke2fs-$arch" "$tree/usr/sbin/mkfs.ext4"
  install -m 0755 "$STATIC/sgdisk-$arch" "$tree/usr/sbin/sgdisk"
fi
if [ -n "${SERVICES:-}" ]; then
  cp "$SERVICES"/*.yaml "$tree/usr/lib/sneakers/services.d/" 2>/dev/null || true
fi
# /etc is read-only; the resolver config lives in /run.
ln -s /run/sneakers/resolv.conf "$tree/etc/resolv.conf"
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
