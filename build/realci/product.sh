#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# product.sh: LAB ONLY, one real product bundle for the real-bundle job
# (build/realci/build.sh), run in the checkout of the commit it's built
# from, with that commit's tools: bundle fill over the service images,
# each pinned manifest signed with the lab key, the production render,
# product.yaml and the import Job, then build/product/build.sh. The stacks
# are the published lab bundles' (the render with the lab's debug log
# level); only the generated box secrets differ, as on any new box. The caller
# signs the header and seals it.
#
# Inputs (environment): VERSION, OUT (the product's directory: it holds
# release-src.yaml), CHARTS (the sneakers-release checkout), LAYOUTS (its
# service images), KEYS, MIN_BASE, K0S and HELM.
set -euo pipefail
: "${VERSION:?}" "${OUT:?}" "${CHARTS:?}" "${LAYOUTS:?}" "${KEYS:?}" "${MIN_BASE:?}" "${K0S:?}" "${HELM:?}"
b="$OUT"
mkdir -p "$b/sigs" "$b/manifests"
go run ./build/tools/bundle fill --release "$b/release-src.yaml" --layouts "$LAYOUTS" > "$b/release.yaml"
go run ./build/tools/bundle images --release "$b/release.yaml" > "$b/images.txt"
while read -r image dgst; do
  hexd="${dgst#sha256:}"
  go run ./build/tools/bundle manifest --image "$image" --digest "$dgst" --layouts "$LAYOUTS" --out "$b/manifests/$hexd"
  cosign sign-blob --yes --key "$KEYS/cosign.key" --bundle "$b/sigs/$hexd.sigstore.json" \
    --tlog-upload=false --use-signing-config=false "$b/manifests/$hexd" >/dev/null 2>&1
done < "$b/images.txt"
# The lab bundles log at debug, as the published ones did.
printf 'global:\n  logLevel: debug\n' > "$b/lab-values.yaml"
CHARTS="$CHARTS" RELEASE="$b/release.yaml" HELM="$HELM" EXTRA_VALUES="$b/lab-values.yaml" OUT="$b/stacks" bash build/product/sneakers/render.sh
migrate="$(awk '$1 ~ /\/sneakers-migrate$/ { print $1 "@" $2 }' "$b/images.txt")"
[ -n "$migrate" ] || { echo "realci: release.yaml pins no sneakers-migrate image" >&2; exit 1; }
# The checkout may be a pinned commit from before the bundle had a brand.
brand=build/product/sneakers/brand
[ -d "$brand" ] || brand=
inputs="$(RELEASE="$b/release.yaml" STACKS="$b/stacks" PRODUCT_YAML=build/product/sneakers/product.yaml \
  IMPORT_JOB=build/product/sneakers/import-job.yaml BRAND="$brand" bash build/lab/units.sh inputs product)"
# The bundle carries helm only where release.yaml pins it.
helm=()
if [ -n "$(go run ./build/tools/k0spin "$b/release.yaml" amd64 helm)" ]; then helm=(HELM="$HELM"); fi
env -u HELM "${helm[@]}" INPUTS="$inputs" VERSION="$VERSION" ARCH=amd64 CHANNEL=lab MIN_BASE="$MIN_BASE" RELEASE="$b/release.yaml" \
  RELEASE_KEY="$KEYS/cosign.pub" SIGNATURES="$b/sigs" LAYOUTS="$LAYOUTS" K0S="$K0S" \
  RECIPIENT="$KEYS/update.pub" STACKS="$b/stacks" PRODUCT_YAML=build/product/sneakers/product.yaml \
  IMPORT_JOB=build/product/sneakers/import-job.yaml BRAND="$brand" MIGRATE_IMAGE="$migrate" OUT="$b/work" \
  bash build/product/build.sh
