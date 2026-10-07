#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh: the release workflow's build job. It builds everything a
# production release needs, unsigned, and holds no key. The sign job checks
# SHA256SUMS before it signs anything.
#
# Inputs (environment):
#   VERSION        the release version (from the tag)
#   KERNEL         the bzImage (build/kernel/build.sh)
#   KERNELRELEASE  its release string
#   VERITYSETUP    the static veritysetup (build/static/cryptsetup.sh)
#   OPENSSH        directory with the static OpenSSH (build/openssh/build.sh)
#   BUSYBOX        the static busybox (build/busybox/build.sh)
#   SIGNATURES     the org signatures of the pinned images, <hex>.sigstore.json
#                  each (the sneakers-release countersignatures)
#   OUT            the output directory
#   KEYS           the public key directory (default keys/production)
#
# The release.yaml (and its signature) comes from the sneakers-release
# GitHub Release pinned by SNEAKERS_RELEASE_VERSION in build/release/pins.env.
# It isn't trusted here: the publish job's production kit verifies its
# signature, and the root build checks the k0s binary against its pin.
#
# Output in $OUT: sneakers-<version>.efi (unsigned UKI), systemd-bootx64.efi
# (unsigned), root-<version>.img, verity.json, release.yaml,
# release.yaml.sigstore.json, systemd-version, sneakers-artifact and
# sneakers-kit (production pins), and SHA256SUMS over all of them.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${VERSION:?}" "${KERNEL:?}" "${KERNELRELEASE:?}" "${VERITYSETUP:?}" "${OPENSSH:?}" "${BUSYBOX:?}" "${OUT:?}"
: "${SIGNATURES:?sneakers-release publishes no image countersignatures yet; the bundle can't be built without them}"
keys="${KEYS:-$root/keys/production}"
arch=amd64
# shellcheck source=build/release/pins.env
source "$here/pins.env"
: "${SNEAKERS_RELEASE_VERSION:?pin SNEAKERS_RELEASE_VERSION in build/release/pins.env}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
mkdir -p "$OUT"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "release: release.yaml from sneakers-release v$SNEAKERS_RELEASE_VERSION"
base="https://github.com/Sneakers-PAM/sneakers-release/releases/download/v$SNEAKERS_RELEASE_VERSION"
for f in release.yaml release.yaml.sigstore.json; do
  curl -fsSL --retry 3 -o "$OUT/$f" "$base/$f"
done

k0s_version="$(awk '/^ *k0s:/ { k = 1; next } k && /^ *version:/ { print $2; exit }' "$OUT/release.yaml")"
[ -n "$k0s_version" ] || { echo "release: release.yaml names no k0s version" >&2; exit 1; }
echo "release: k0s $k0s_version"
curl -fsSL --retry 3 -o "$work/k0s" "https://github.com/k0sproject/k0s/releases/download/$k0s_version/k0s-$k0s_version-$arch"

pkg=github.com/Sneakers-PAM/sneakers-appliance/internal/release
b64() { base64 -w0 < "$1"; }
pins="-X $pkg.Channel=production -X $pkg.Version=$VERSION \
  -X $pkg.ReleaseKey=$(b64 "$keys/cosign.pub") -X $pkg.DBCert=$(b64 "$keys/db.crt") \
  -X $pkg.PKCert=$(b64 "$keys/PK.crt") -X $pkg.KEKCert=$(b64 "$keys/KEK.crt")"

echo "release: bundle"
RELEASE="$OUT/release.yaml" RELEASE_KEY="$keys/cosign.pub" SIGNATURES="$SIGNATURES" ARCH="$arch" OUT="$work/images" \
  bash "$root/build/bundle/build.sh"

echo "release: root"
PINS_LDFLAGS="$pins" VERSION="$VERSION" ARCH="$arch" RELEASE="$OUT/release.yaml" K0S="$work/k0s" OPENSSH="$OPENSSH" \
  BUSYBOX="$BUSYBOX" IMAGES="$work/images" OUT="$work/root" bash "$root/build/root/build.sh"
cp "$work/root/root-$VERSION.img" "$work/root/verity.json" "$OUT/"

echo "release: UKI (unsigned)"
KERNEL="$KERNEL" VERITYSETUP="$VERITYSETUP" VERITY_JSON="$OUT/verity.json" \
  VERSION="$VERSION" OUT="$work/uki" UNAME="$KERNELRELEASE" bash "$root/build/uki/assemble.sh"
cp "$work/uki/sneakers-$VERSION.efi" "$OUT/"
cp /usr/lib/systemd/boot/efi/systemd-bootx64.efi "$OUT/"
dpkg-query -W -f='${Version}' systemd-boot-efi > "$OUT/systemd-version"

echo "release: tools"
CGO_ENABLED=0 go build -trimpath -o "$OUT/sneakers-artifact" -ldflags "-s -w" "$root/cmd/sneakers-artifact"
CGO_ENABLED=0 go build -trimpath -o "$OUT/sneakers-kit" -ldflags "-s -w $pins" "$root/cmd/sneakers-kit"

( cd "$OUT" && sha256sum -- * | grep -v ' SHA256SUMS$' > SHA256SUMS )
echo "release: built $VERSION ($arch), unsigned"
