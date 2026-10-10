#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# render.sh: the Sneakers product bundle's stacks, rendered from
# sneakers-release's charts/sneakers, the same way for every channel: two
# helm renders (the MCP switch off and on) over the small-box example with
# values.yaml, turned into k0s stacks by build/tools/stack, plus the edge.
# Pass OUT to build/product/build.sh as STACKS, with product.yaml as
# PRODUCT_YAML.
#
#   OUT/sneakers/sneakers.yaml          the product, always on
#   OUT/sneakers-mcp/sneakers-mcp.yaml  the MCP server, Hydra and the
#                                       sneakers-mcp-switch ConfigMap, applied
#                                       while the MCP switch is on
#   OUT/sneakers-import/sneakers-import.yaml
#                                       the migrate service account, applied
#                                       while an import is open (import-stack.yaml,
#                                       docs/import.md)
#   OUT/edge/edge.yaml                  the interim edge on 443 (build/lab/stacks/edge)
#
# The main stack lists the migrate caller in the vault and audit and admits
# it in the NetworkPolicies (sneakers-release's
# migrate/deploy/migrate-callers-values.yaml); with the import closed there is
# no sneakers-migrate service account, so nothing runs as it.
#
# The stacks carry no secret value: every Secret they read is a box secret
# product.yaml declares, made on each box (internal/boxsecrets).
#
# The gateway gets the release's version (metadata.version) as
# SNEAKERS_PRODUCT_VERSION, and the box's values (values.yaml) for the
# product's About and diagnostics.
#
# Inputs (environment):
#   CHARTS        a sneakers-release checkout (its charts/ are copied, never changed)
#   RELEASE       the release.yaml every image is pinned in, by digest (for a
#                 release, the one bundle fill made)
#   HELM          the helm binary (default: helm on the PATH)
#   EXTRA_VALUES  a values file layered last (optional; a lab build's own)
#   OUT           the stacks directory (empty or missing)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
: "${CHARTS:?}" "${RELEASE:?}" "${OUT:?}"
helm="${HELM:-helm}"
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then
  echo "render: $OUT isn't empty" >&2
  exit 1
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export HELM_CACHE_HOME="$work/helm/cache" HELM_CONFIG_HOME="$work/helm/config" HELM_DATA_HOME="$work/helm/data"
mkdir -p "$work/release/scripts" "$work/bin"
cp -r "$CHARTS/charts" "$work/release/charts"
install -m 0755 "$CHARTS/scripts/build-deps.sh" "$work/release/scripts/"
ln -s "$(command -v "$helm")" "$work/bin/helm"
chart="$work/release/charts/sneakers"
echo "render: charts from $(git -C "$CHARTS" rev-parse HEAD 2>/dev/null || echo "$CHARTS")"
# sneakers-release's own dependency build: the library into each service
# chart, then the umbrella.
PATH="$work/bin:$PATH" bash "$work/release/scripts/build-deps.sh" >/dev/null
values=(-f "$chart/examples/values-small-box.yaml" -f "$CHARTS/migrate/deploy/migrate-callers-values.yaml" -f "$here/values.yaml")
[ -z "${EXTRA_VALUES:-}" ] || values+=(-f "$EXTRA_VALUES")
# The product's own version for its About: the release's.
product_version="$(go run "$root/build/tools/bundle" version --release "$RELEASE")"
values+=(--set-string "gateway.env.SNEAKERS_PRODUCT_VERSION=$product_version")
echo "render: product version $product_version"
"$helm" template sneakers "$chart" -n sneakers --skip-tests "${values[@]}" > "$work/off.yaml"
"$helm" template sneakers "$chart" -n sneakers --skip-tests "${values[@]}" -f "$here/values-mcp-on.yaml" > "$work/on.yaml"
mkdir -p "$OUT"
go run "$root/build/tools/stack" --release "$RELEASE" --product-yaml "$here/product.yaml" \
  --off "$work/off.yaml" --on "$work/on.yaml" --out "$OUT" \
  --namespace sneakers --stack sneakers --switch-stack sneakers-mcp \
  --switch-configmap sneakers-mcp-switch --switch-from sneakers-gateway,sneakers-web-staff \
  --data /var/lib/sneakers-data
mkdir -p "$OUT/sneakers-import"
install -m 0644 "$here/import-stack.yaml" "$OUT/sneakers-import/sneakers-import.yaml"
mkdir -p "$OUT/edge"
install -m 0644 "$root/build/lab/stacks/edge/edge.yaml" "$OUT/edge/edge.yaml"
echo "render: stacks $(cd "$OUT" && echo */ | tr -d /)"
