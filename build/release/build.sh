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
#   STATIC         directory with the static cryptsetup, veritysetup, mke2fs
#                  and sgdisk and their stamps (build/static), which the root
#                  carries for first boot
#   RELEASE        the release.yaml: sneakers-release's manifest/release.yaml
#                  at the commit build/release/pins.env pins
#   CHARTS         that sneakers-release checkout: the product's stacks are
#                  rendered from its charts (build/product/sneakers/render.sh)
#   SERVICE_IMAGES the service images the images job built from release.yaml's
#                  build blocks, an OCI layout per service (build/release/images.sh)
#   WEB            a sneakers-web checkout at the commit pins.env pins: the
#                  :8443 pages are built from it (build/lab/pages.sh)
#   OUT            the output directory
#   KEYS           the public key directory (default keys/production)
#
# release.yaml isn't trusted here and nothing is signed: the digest of each
# service image built is put in place of its placeholder (bundle fill), and
# the sign job countersigns that release.yaml and the manifest of every
# image it pins with the release key, then builds the product bundle from
# them. A placeholder with no image built, or any other image not pinned by
# a digest, is refused before anything is fetched.
#
# Output in $OUT: sneakers-<version>.efi (unsigned UKI), systemd-bootx64.efi
# (unsigned), root-<version>.img, verity.json, release.yaml (with the built
# digests), stacks/ (the product's k0s stacks) and product.yaml (the product
# bundle's), 
# systemd-version, k0s and helm (checked against release.yaml's pins),
# images.txt ("<image> <digest>" for every pinned image) with manifests/<hex>
# (each image's manifest or index bytes, which hash to its digest, for the
# sign job to countersign), pages/ (the :8443 pages, also in the root, for
# the Base Web unit), inputs-baseOS (the Base OS input digest,
# build/lab/units.sh inputs baseOS), sneakers-artifact and sneakers-kit
# (production pins), and SHA256SUMS over all of them. The base root carries
# no k0s or images.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${VERSION:?}" "${KERNEL:?}" "${KERNELRELEASE:?}" "${VERITYSETUP:?}" "${OPENSSH:?}" "${BUSYBOX:?}" "${STATIC:?}" "${OUT:?}"
: "${RELEASE:?set RELEASE to manifest/release.yaml from sneakers-release at the pinned commit}"
: "${WEB:?set WEB to the sneakers-web checkout at the pinned commit}"
: "${CHARTS:?set CHARTS to the sneakers-release checkout at the pinned commit}"
: "${SERVICE_IMAGES:?set SERVICE_IMAGES to the service images build/release/images.sh built}"
keys="${KEYS:-$root/keys/production}"
arch=amd64
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
tools="$(mktemp -d)"
trap 'rm -rf "$tools"' EXIT
CGO_ENABLED=0 go build -trimpath -o "$tools/bundle" "$root/build/tools/bundle"
"$tools/bundle" fill --release "$RELEASE" --layouts "$SERVICE_IMAGES" > "$tools/release.yaml"
"$tools/bundle" images --release "$tools/release.yaml" > "$tools/images.txt"
mkdir -p "$OUT"
work="$(mktemp -d)"
trap 'rm -rf "$tools" "$work"' EXIT

echo "release: release.yaml $(sha256sum < "$RELEASE" | cut -d' ' -f1), with the built digests $(sha256sum < "$tools/release.yaml" | cut -d' ' -f1), $(wc -l < "$tools/images.txt") images"
install -m 0644 "$tools/release.yaml" "$OUT/release.yaml"
install -m 0644 "$tools/images.txt" "$OUT/images.txt"
rm -rf "$OUT/manifests"
mkdir -p "$OUT/manifests"
while read -r image dgst; do
  hexd="${dgst#sha256:}"
  "$tools/bundle" manifest --image "$image" --digest "$dgst" --layouts "$SERVICE_IMAGES" --out "$OUT/manifests/$hexd"
  got="$(sha256sum < "$OUT/manifests/$hexd" | cut -d' ' -f1)"
  [ "$got" = "$hexd" ] || { echo "release: $image's manifest hashes to $got, not its pin $dgst" >&2; exit 1; }
done < "$OUT/images.txt"

k0s_version="$(awk '/^ *k0s:/ { k = 1; next } k && /^ *version:/ { print $2; exit }' "$OUT/release.yaml")"
[ -n "$k0s_version" ] || { echo "release: release.yaml names no k0s version" >&2; exit 1; }
echo "release: k0s $k0s_version"
curl -fsSL --retry 3 -o "$OUT/k0s" "https://github.com/k0sproject/k0s/releases/download/${k0s_version//+/%2B}/k0s-$k0s_version-$arch"
want="$(go run "$root/build/tools/k0spin" "$OUT/release.yaml" "$arch")"
[ "$(sha256sum < "$OUT/k0s" | cut -d' ' -f1)" = "$want" ] || { echo "release: k0s $k0s_version isn't the binary release.yaml pins ($want)" >&2; exit 1; }
# helm ships when release.yaml pins it.
helm_version="$(awk '/^ *helm:/ { h = 1; next } h && /^ *version:/ { print $2; exit }' "$OUT/release.yaml")"
if [ -n "$helm_version" ]; then
  echo "release: helm $helm_version"
  curl -fsSL --retry 3 -o "$work/helm.tar.gz" "https://get.helm.sh/helm-$helm_version-linux-$arch.tar.gz"
  tar -xzOf "$work/helm.tar.gz" "linux-$arch/helm" > "$OUT/helm"
  want="$(go run "$root/build/tools/k0spin" "$OUT/release.yaml" "$arch" helm)"
  [ "$(sha256sum < "$OUT/helm" | cut -d' ' -f1)" = "$want" ] || { echo "release: helm $helm_version isn't the binary release.yaml pins ($want)" >&2; exit 1; }
fi

# The product's stacks, rendered from the pinned charts with the helm
# build/ci/versions.env pins (the same render a lab bundle uses).
# shellcheck source=build/ci/versions.env
source "$root/build/ci/versions.env"
curl -fsSL --retry 3 -o "$work/render-helm.tar.gz" "https://get.helm.sh/helm-$HELM_VERSION-linux-$arch.tar.gz"
[ "$(sha256sum < "$work/render-helm.tar.gz" | cut -d' ' -f1)" = "$HELM_TGZ_SHA256_AMD64" ] || { echo "release: helm $HELM_VERSION isn't the tarball versions.env pins" >&2; exit 1; }
tar -xzOf "$work/render-helm.tar.gz" "linux-$arch/helm" > "$work/render-helm"
chmod 0755 "$work/render-helm"
rm -rf "$OUT/stacks"
CHARTS="$CHARTS" RELEASE="$OUT/release.yaml" HELM="$work/render-helm" OUT="$OUT/stacks" bash "$root/build/product/sneakers/render.sh"
install -m 0644 "$root/build/product/sneakers/product.yaml" "$OUT/product.yaml"

pkg=github.com/Sneakers-PAM/sneakers-appliance/internal/release
b64() { base64 -w0 < "$1"; }
pins="-X $pkg.Channel=production -X $pkg.Version=$VERSION \
  -X $pkg.ReleaseKey=$(b64 "$keys/cosign.pub") -X $pkg.DBCert=$(b64 "$keys/db.crt") \
  -X $pkg.PKCert=$(b64 "$keys/PK.crt") -X $pkg.KEKCert=$(b64 "$keys/KEK.crt")"

echo "release: :8443 pages"
WEB="$WEB" VERSION="$VERSION" OUT="$OUT/pages" bash "$root/build/lab/pages.sh"

echo "release: root"
PINS_LDFLAGS="$pins" VERSION="$VERSION" ARCH="$arch" RELEASE="$OUT/release.yaml" OPENSSH="$OPENSSH" \
  BUSYBOX="$BUSYBOX" STATIC="$STATIC" OSADMIN_ASSETS="$OUT/pages" OUT="$work/root" bash "$root/build/root/build.sh"
cp "$work/root/root-$VERSION.img" "$work/root/verity.json" "$OUT/"

echo "release: UKI (unsigned)"
KERNEL="$KERNEL" VERITYSETUP="$VERITYSETUP" VERITY_JSON="$OUT/verity.json" \
  VERSION="$VERSION" OUT="$work/uki" UNAME="$KERNELRELEASE" bash "$root/build/uki/assemble.sh"
cp "$work/uki/sneakers-$VERSION.efi" "$OUT/"
cp /usr/lib/systemd/boot/efi/systemd-bootx64.efi "$OUT/"
dpkg-query -W -f='${Version}' systemd-boot-efi > "$OUT/systemd-version"

# The sign job seals the units without these components, so the Base OS
# input digest is taken here, from what this build took.
KERNEL="$KERNEL" VERITYSETUP="$VERITYSETUP" BUSYBOX="$BUSYBOX" OPENSSH="$OPENSSH" STATIC="$STATIC" \
  bash "$root/build/lab/units.sh" inputs baseOS > "$OUT/inputs-baseOS"

echo "release: tools"
CGO_ENABLED=0 go build -trimpath -o "$OUT/sneakers-artifact" -ldflags "-s -w" "$root/cmd/sneakers-artifact"
CGO_ENABLED=0 go build -trimpath -o "$OUT/sneakers-kit" -ldflags "-s -w $pins" "$root/cmd/sneakers-kit"

( cd "$OUT" && find . -type f ! -name SHA256SUMS -printf '%P\0' | LC_ALL=C sort -z | xargs -0 sha256sum -- > SHA256SUMS )
echo "release: built $VERSION ($arch), unsigned"
