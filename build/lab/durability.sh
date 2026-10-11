#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# durability.sh: LAB ONLY, the image suite's two durability product
# bundles (test/image/k0s, docs/upgrades.md#the-phases), from a
# build/lab/build.sh run's work directory and keys. Both carry the bundled
# PostgreSQL rendered from sneakers-release's charts/postgres (the same
# chart, values aside, the Sneakers product runs) through build/tools/stack,
# so its volume is the box's hostPath under /var/lib/sneakers-data and its
# passwords are box secrets, and a client that holds a session on it:
#
#   OUT/phaseless/sneakers-product-*.bin  everything in one always-on stack,
#                                         as a product from before the phases
#                                         (product-phaseless.yaml), version
#                                         <VERSION>.1
#   OUT/phased/sneakers-product-*.bin     the same render in phases, the
#                                         database first (product-phased.yaml),
#                                         version <VERSION>.2, the update
#
# Each also has the lab's hello page (always on) and edge, so the box
# counts the product as up. The suite installs the first, writes rows,
# updates to the second, reboots and powers the box off, and counts the
# rows each time (the lab hook, build/lab/overlay).
#
# Inputs (environment):
#   WORK      the build/lab/build.sh work directory: release.yaml,
#             bundle-tool, image-sigs/
#   K0S, HELM the k0s and helm binaries that run bundled
#   KEYS      that run's lab keys (cosign.key, cosign.pub, update.pub)
#   VERSION   that run's version; the bundles fit its base and newer
#   CHARTS    a sneakers-release checkout (default: SNEAKERS_RELEASE_COMMIT
#             from build/ci/versions.env, fetched)
#   OUT       the output directory
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${WORK:?}" "${KEYS:?}" "${VERSION:?}" "${K0S:?}" "${HELM:?}" "${OUT:?}"
src="$here/durability"
work="$WORK/durability"
rm -rf "$work"
mkdir -p "$work" "$OUT"
say() { echo "durability: $*"; }
sign_blob() { # file bundle
  cosign sign-blob --yes --key "$KEYS/cosign.key" --bundle "$2" \
    --tlog-upload=false --use-signing-config=false "$1" >/dev/null 2>&1
}
# shellcheck source=build/ci/versions.env
source "$root/build/ci/versions.env"

charts="${CHARTS:-}"
if [ -z "$charts" ]; then
  charts="$work/sneakers-release"
  say "charts from sneakers-release at $SNEAKERS_RELEASE_COMMIT"
  git init -q "$charts"
  git -C "$charts" fetch -q --depth 1 https://github.com/Sneakers-PAM/sneakers-release.git "$SNEAKERS_RELEASE_COMMIT"
  git -C "$charts" checkout -q FETCH_HEAD
fi

# The PostgreSQL image the chart pins, added to the lab release's
# third-party images and signed with the lab key like the rest.
pg_image="$(awk '/^image:/ { i = 1; next } i && /^ *repository:/ { print $2; exit }' "$charts/charts/postgres/values.yaml")"
pg_digest="$(awk '/^image:/ { i = 1; next } i && /^ *digest:/ { print $2; exit }' "$charts/charts/postgres/values.yaml")"
[ -n "$pg_image" ] && [ -n "$pg_digest" ] || { echo "durability: charts/postgres pins no image digest" >&2; exit 1; }
say "PostgreSQL $pg_image@$pg_digest"
awk -v img="$pg_image" -v dg="$pg_digest" '
  { print }
  /^  thirdParty:$/ { print "    postgres:"; print "      image: " img; print "      digest: " dg }
' "$WORK/release.yaml" > "$work/release.yaml"
grep -q "digest: $pg_digest" "$work/release.yaml" || { echo "durability: the lab release.yaml has no thirdParty block" >&2; exit 1; }
sign_blob "$work/release.yaml" "$work/release.yaml.sigstore.json"
mkdir -p "$work/image-sigs"
cp "$WORK"/image-sigs/*.sigstore.json "$work/image-sigs/"
"$WORK/bundle-tool" manifest --image "$pg_image" --digest "$pg_digest" --out "$work/postgres.manifest"
sign_blob "$work/postgres.manifest" "$work/image-sigs/${pg_digest#sha256:}.sigstore.json"

say "render"
# The bundled helm renders the chart; the build keeps its copy as it
# bundles it, so this runs one of its own.
helm="$work/helm-render"
install -m 0755 "$HELM" "$helm"
export HELM_CACHE_HOME="$work/helm-home/cache" HELM_CONFIG_HOME="$work/helm-home/config" HELM_DATA_HOME="$work/helm-home/data"
{
  "$helm" template sneakers "$charts/charts/postgres" -n sneakers -f "$src/values.yaml"
  echo "---"
  cat "$src/client.yaml"
} > "$work/render.yaml"

# The bundles fit the base this run built; their own versions follow it.
base="$VERSION"
n=0
for kind in phaseless phased; do
  n=$((n + 1))
  stacks="$work/$kind/stacks"
  mkdir -p "$stacks"
  go run "$root/build/tools/stack" --release "$work/release.yaml" --product-yaml "$src/product-$kind.yaml" \
    --off "$work/render.yaml" --out "$stacks" --namespace sneakers --stack durability --data /var/lib/sneakers-data
  # The hello page, always on (no phase), and the edge that serves it.
  mkdir -p "$stacks/hello" "$stacks/edge"
  {
    cat "$root/build/lab/stacks/hello/hello.yaml"
    echo "---"
    grep -v 'sneakers-appliance/phase' "$root/build/lab/stacks/lab-front/lab-front.yaml"
  } > "$stacks/hello/hello.yaml"
  install -m 0644 "$root/build/lab/stacks/edge/edge.yaml" "$stacks/edge/edge.yaml"
  say "$kind stacks: $(cd "$stacks" && echo */ | tr -d /)"
  VERSION="$base.$n" CHANNEL=lab MIN_BASE="$base" BASES="$base" RELEASE="$work/release.yaml" RELEASE_KEY="$KEYS/cosign.pub" \
    SIGNATURES="$work/image-sigs" K0S="$K0S" HELM="$HELM" RECIPIENT="$KEYS/update.pub" STACKS="$stacks" \
    PRODUCT_YAML="$src/product-$kind.yaml" OUT="$work/$kind/product" bash "$root/build/product/build.sh"
  sign_blob "$work/$kind/product/bin/header.json" "$work/$kind/product/bin/header.sigstore.json"
  rm -rf "${OUT:?}/$kind"
  bin="$(go run "$root/cmd/sneakers-artifact" bin-seal --work "$work/$kind/product/bin" --bundle "$work/$kind/product/bin/header.sigstore.json" --out "$OUT/$kind")"
  rm -rf "$work/$kind/product/tree"
  say "$kind: $(basename "$bin"), version $base.$n, $(stat -c %s "$bin") bytes"
done
