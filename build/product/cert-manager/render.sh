#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# render.sh: the product bundle's cert-manager stack (OUT/cert-manager/
# cert-manager.yaml), applied by k0s ahead of everything that names a
# cert-manager kind (the box-acme stack, internal/acme). It is upstream's
# static manifest for the version release.yaml pins, taken only at the
# checksum recorded in upstream.sha256, with every cert-manager image
# named by the digest release.yaml pins and never pulled (the bundle
# carries them). The controller starts its HTTP-01 solver pods from the
# pinned acmesolver, not from a tag the airgapped box can't pull.
#
# Inputs (environment):
#   RELEASE   the release.yaml the images are pinned in
#   OUT       the stacks directory (empty or missing)
#   UPSTREAM  the upstream cert-manager.yaml (optional; a test's own, else
#             fetched from the release's GitHub download)
#   SUMS      the file of "<version> <sha256>" lines (default: upstream.sha256)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${RELEASE:?}" "${OUT:?}"
sums="${SUMS:-$here/upstream.sha256}"
fail() { echo "cert-manager: $*" >&2; exit 1; }
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then fail "$OUT isn't empty"; fi

# pin NAME FIELD: a field of spec.platform.NAME in release.yaml.
pin() {
  awk -v n="$1" -v f="$2" '
    /^  platform:/ { p = 1; next }
    p && /^  [A-Za-z]/ { p = 0 }
    p && $0 ~ ("^    " n ":") { s = 1; next }
    p && s && /^    [A-Za-z]/ { s = 0 }
    p && s && $1 == f ":" { gsub(/"/, "", $2); print $2; exit }
  ' "$RELEASE"
}

version="$(pin cert-manager-controller version)"
[ -n "$version" ] || fail "release.yaml pins no cert-manager-controller"
want="$(awk -v v="$version" '$1 == v { print $2 }' "$sums")"
[ -n "$want" ] || fail "no checksum recorded for the pinned version $version (add it to upstream.sha256 with the pin)"

images=(controller webhook cainjector acmesolver)
declare -A repo dig
for i in "${images[@]}"; do
  n="cert-manager-$i"
  repo[$i]="$(pin "$n" image)"
  dig[$i]="$(pin "$n" digest)"
  [ -n "${repo[$i]}" ] && [ -n "${dig[$i]}" ] || fail "release.yaml pins no $n (spec.platform)"
  case "${dig[$i]}" in sha256:????????????????????????????????????????????????????????????????) ;; *) fail "$n's digest ${dig[$i]} isn't a sha256 digest" ;; esac
  [ "$(pin "$n" version)" = "$version" ] || fail "$n isn't at $version, the controller's version"
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
src="${UPSTREAM:-}"
if [ -z "$src" ]; then
  src="$work/cert-manager.yaml"
  curl -fsSL --retry 3 -o "$src" "https://github.com/cert-manager/cert-manager/releases/download/$version/cert-manager.yaml"
fi
got="$(sha256sum "$src" | cut -d' ' -f1)"
[ "$got" = "$want" ] || fail "upstream $version has checksum $got; upstream.sha256 records $want"

out="$work/stack.yaml"
cp "$src" "$out"
for i in "${images[@]}"; do
  r="${repo[$i]}"
  # Tags in an image field and in the controller's solver flag become the digest.
  sed -i.bak -E "s#${r}:${version}#${r}@${dig[$i]}#g" "$out"
done
rm -f "$out.bak"
sed -i.bak 's/imagePullPolicy: IfNotPresent/imagePullPolicy: Never/' "$out" && rm -f "$out.bak"
if grep -nE "quay.io/jetstack/[a-z-]+:v[0-9]" "$out"; then fail "an image is still named by tag"; fi
grep -qF -- "--acme-http01-solver-image=${repo[acmesolver]}@${dig[acmesolver]}" "$out" || fail "the controller doesn't start solvers from the pinned acmesolver"

mkdir -p "$OUT/cert-manager"
install -m 0644 "$out" "$OUT/cert-manager/cert-manager.yaml"
echo "cert-manager: $version stack written"
