#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh: LAB ONLY, what the browser journeys boot and install
# (docs/testing.md#the-browser-journeys), signed with one lab key set made
# for the run:
#
#   OUT/lab/           a lab release of this commit (build/lab/build.sh)
#                      with the :8443 pages built from sneakers-web at
#                      SNEAKERS_WEB_COMMIT (build/release/pins.env), and its
#                      raw disk
#   OUT/product.bin    the real Sneakers product from sneakers-release at
#                      SNEAKERS_RELEASE_COMMIT, built the way the real-bundle
#                      job builds its products (build/realci/product.sh):
#                      the service images, bundle fill, every pinned
#                      manifest signed with the lab key, the production
#                      render, then sealed and checked with the lab UKI
#   OUT/journeys.env   SNEAKERS_IMAGE, SNEAKERS_JOURNEYS_PRODUCT and
#                      SNEAKERS_JOURNEYS_PRODUCT_VERSION, for the driver
#                      (test/image/journeys)
#
# Inputs (environment):
#   KEYS        a fresh directory for the lab keys (CI: a tmpfs)
#   OUT         the output directory
#   LAYOUTS     the service image layouts for SNEAKERS_RELEASE_COMMIT
#               (OUT/layouts by default); built when it has no .done, so a
#               cached copy is used as it is
#   KERNEL, KERNELRELEASE, VERITYSETUP, OPENSSH, BUSYBOX, STATIC
#               the components, as build/lab/build.sh takes them
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${KEYS:?}" "${OUT:?}" "${KERNEL:?}" "${KERNELRELEASE:?}" "${VERITYSETUP:?}" "${OPENSSH:?}" "${BUSYBOX:?}" "${STATIC:?}"
# shellcheck source=build/release/pins.env
source "$root/build/release/pins.env"
say() { echo "journeys: $*"; }
mkdir -p "$OUT"
out="$(cd "$OUT" && pwd)"
layouts="${LAYOUTS:-$out/layouts}"
mkdir -p "$layouts"
layouts="$(cd "$layouts" && pwd)"
export COSIGN_PASSWORD=""
version="0.1.0-lab.journeys"

# fetch <repo> <commit> <dir>: a shallow checkout of one commit.
fetch() {
  if [ ! -d "$3/.git" ]; then
    git init -q "$3"
    git -C "$3" fetch -q --depth 1 "https://github.com/$1.git" "$2"
    git -C "$3" checkout -q FETCH_HEAD
  fi
  [ "$(git -C "$3" rev-parse HEAD)" = "$2" ] || { echo "journeys: $1 fetched $(git -C "$3" rev-parse HEAD) for $2" >&2; exit 1; }
}

start="$(date +%s)"
fetch "$SNEAKERS_WEB_REPO" "$SNEAKERS_WEB_COMMIT" "$out/web"
say "the lab release with the :8443 pages from sneakers-web ${SNEAKERS_WEB_COMMIT:0:7}"
(cd "$root" && WEB="$out/web" OUT="$out/lab" bash build/lab/build.sh) > "$out/lab.log" 2>&1 || { tail -40 "$out/lab.log" >&2; exit 1; }
base="$(cat "$out/lab/version")"
# The k0s and helm the lab build fetched and checked (build/ci/versions.env),
# made executable for the product's render.
mkdir -p "$out/bin"
install -m 0755 "$out/lab/work/k0s" "$out/bin/k0s"
install -m 0755 "$out/lab/work/helm" "$out/bin/helm"
say "base $base in $(( $(date +%s) - start ))s"

start="$(date +%s)"
fetch "$SNEAKERS_RELEASE_REPO" "$SNEAKERS_RELEASE_COMMIT" "$out/release"
if [ ! -e "$layouts/.done" ]; then
  say "service images for sneakers-release ${SNEAKERS_RELEASE_COMMIT:0:7}"
  (cd "$root" && RELEASE="$out/release/manifest/release.yaml" OUT="$layouts" bash build/release/images.sh) > "$out/images.log" 2>&1 \
    || { tail -40 "$out/images.log" >&2; exit 1; }
  : > "$layouts/.done"
fi
b="$out/product"
mkdir -p "$b"
sed "0,/^  version: .*$/s//  version: $version/" "$out/release/manifest/release.yaml" > "$b/release-src.yaml"
grep -q "^  version: $version$" "$b/release-src.yaml"
(cd "$root" && VERSION="$version" OUT="$b" CHARTS="$out/release" LAYOUTS="$layouts" KEYS="$KEYS" MIN_BASE="$base" \
  K0S="$out/bin/k0s" HELM="$out/bin/helm" bash build/realci/product.sh) > "$out/product.log" 2>&1 \
  || { tail -40 "$out/product.log" >&2; exit 1; }
tool="$out/sneakers-artifact"
(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$tool" ./cmd/sneakers-artifact)
cosign sign-blob --yes --key "$KEYS/cosign.key" --bundle "$b/work/bin/header.sigstore.json" \
  --tlog-upload=false --use-signing-config=false "$b/work/bin/header.json" >/dev/null 2>&1
bin="$("$tool" bin-seal --work "$b/work/bin" --bundle "$b/work/bin/header.sigstore.json" --out "$b/out")"
cp "$bin" "$out/product.bin"
"$tool" bin-verify --release-key "$KEYS/cosign.pub" --channel lab --identity-uki "$out/lab/work/sneakers-$base.efi" "$out/product.bin" >/dev/null
# The unpacked bundle under the work directory isn't needed again.
rm -rf "$b/work/tree"
say "product $version, $(stat -c %s "$out/product.bin") bytes, opens with the lab UKI, in $(( $(date +%s) - start ))s"

cat > "$out/journeys.env" <<ENV
SNEAKERS_IMAGE=$(ls "$out"/lab/disk/*.raw)
SNEAKERS_JOURNEYS_PRODUCT=$out/product.bin
SNEAKERS_JOURNEYS_PRODUCT_VERSION=$version
ENV
say "done: $(tr '\n' ' ' < "$out/journeys.env")"
