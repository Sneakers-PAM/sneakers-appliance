#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The production product bundle's stacks, rendered by render.sh from
# sneakers-release's charts, are complete and carry nothing of a lab build:
#
#   - every component product.yaml names is pinned in release.yaml, and
#     every service image release.yaml pins runs in a stack;
#   - every container runs an image pinned by digest, never pulled;
#   - no stack carries a Secret (each box makes its own), and every
#     Secret a workload reads is a box secret product.yaml declares
#     (build/tools/stack refuses otherwise);
#   - no lab value: no lab registry or host, no debug or console logging, no
#     dev-only switch, no "lab" in a name or value;
#   - render.sh refuses a non-empty OUT, and a values overlay that brings
#     a Secret no box makes.
#
# CHARTS is a sneakers-release checkout; without it the test fetches the
# commit build/release/pins.env pins (or main while that's empty). The
# service digests, placeholders in git, are filled with stand-ins here.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

charts="${CHARTS:-}"
if [ -z "$charts" ]; then
  # shellcheck source=build/release/pins.env
  source "$root/build/release/pins.env"
  charts="$work/sneakers-release"
  git init -q "$charts"
  git -C "$charts" fetch -q --depth 1 "https://github.com/${SNEAKERS_RELEASE_REPO}.git" "${SNEAKERS_RELEASE_COMMIT:-main}"
  git -C "$charts" checkout -q FETCH_HEAD
fi
helm="${HELM:-}"
if [ -z "$helm" ]; then
  # shellcheck source=build/ci/versions.env
  source "$root/build/ci/versions.env"
  curl -fsSL --retry 3 -o "$work/helm.tar.gz" "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz"
  [ "$(sha256sum < "$work/helm.tar.gz" | cut -d' ' -f1)" = "$HELM_TGZ_SHA256_AMD64" ] || fail "helm $HELM_VERSION isn't the pinned tarball"
  tar -xzOf "$work/helm.tar.gz" linux-amd64/helm > "$work/helm"
  chmod 0755 "$work/helm"
  helm="$work/helm"
fi

# A stand-in digest for each service image, as bundle fill leaves them.
n=0
while IFS= read -r line; do
  if [[ "$line" == *"sha256:TBD-at-release"* ]]; then
    n=$((n + 1))
    line="${line/sha256:TBD-at-release/sha256:$(printf '%064x' "$n")}"
  fi
  printf '%s\n' "$line"
done < "$charts/manifest/release.yaml" > "$work/release.yaml"
[ "$n" -gt 0 ] || fail "release.yaml has no service placeholders to stand in for"

out="$work/stacks"
CHARTS="$charts" RELEASE="$work/release.yaml" HELM="$helm" OUT="$out" bash "$here/render.sh" > "$work/render.log"
for st in sneakers sneakers-mcp edge; do
  [ -s "$out/$st/$st.yaml" ] || fail "no $st stack"
done
echo "ok: rendered $(cd "$out" && echo */ | tr -d /)"

# Complete: every component pinned, every service run.
go run "$root/build/tools/bundle" images --release "$work/release.yaml" > "$work/pinned"
for c in $(sed -n 's/.*image: \([a-z0-9._-]*\)}.*/\1/p' "$here/product.yaml"); do
  grep -q "/$c sha256:" "$work/pinned" || fail "the component $c isn't pinned in release.yaml"
done
go run "$root/build/tools/bundle" sources --release "$charts/manifest/release.yaml" | while read -r _ image _; do
  grep -qh "image: $image@sha256:" "$out"/*/*.yaml || fail "no stack runs $image"
done
echo "ok: every component is pinned and every service image runs in a stack"

# Pinned by digest and never pulled.
if grep -h '^ *image: ' "$out"/*/*.yaml | grep -v '@sha256:[0-9a-f]\{64\}$' | grep -q .; then
  fail "an image isn't pinned by digest: $(grep -h '^ *image: ' "$out"/*/*.yaml | grep -v '@sha256:' | head -1)"
fi
if grep -h 'imagePullPolicy:' "$out"/sneakers*/*.yaml | grep -vq 'Never'; then
  fail "a container may pull its image"
fi
echo "ok: every image is pinned by digest and never pulled"

# No Secret value in any stack.
if grep -l '^kind: Secret$' "$out"/sneakers*/*.yaml; then fail "a stack carries a Secret"; fi
echo "ok: no stack carries a Secret"

# Nothing of a lab build.
lab='(^|[^A-Za-z])[Ll][Aa][Bb]([^A-Za-z]|$)|127\.0\.0\.1:5[0-9]{3}/|localhost:5000|LOG_LEVEL: (debug|trace)|LOG_FORMAT: console|DEV_QUICK_LOGIN: "?true|DEV_UI_ISSUE_COPY: "?true|ENVIRONMENT: (dev|development|test|lab)'
if grep -nE "$lab" "$out"/sneakers*/*.yaml "$here/values.yaml" "$here/values-mcp-on.yaml" "$work/release.yaml" > "$work/lab.txt"; then
  head -5 "$work/lab.txt" >&2
  fail "a lab value in the production stacks"
fi
if grep -h '^ *image: ' "$out"/*/*.yaml | grep -vE 'image: (ghcr\.io|docker\.io|quay\.io)/' | grep -q .; then
  fail "an image from a registry that isn't ghcr.io, docker.io or quay.io"
fi
echo "ok: no lab value"

# Refusals.
if CHARTS="$charts" RELEASE="$work/release.yaml" HELM="$helm" OUT="$out" bash "$here/render.sh" > /dev/null 2>&1; then
  fail "rendered into a non-empty OUT"
fi
cat > "$work/lab-secret.yaml" <<'YAML'
vault:
  secretEnv:
    VAULT_ROOT_KEK:
      secretName: sneakers-lab-secrets
YAML
if CHARTS="$charts" RELEASE="$work/release.yaml" HELM="$helm" EXTRA_VALUES="$work/lab-secret.yaml" OUT="$work/refused" bash "$here/render.sh" > "$work/refused.log" 2>&1; then
  fail "rendered a workload reading a Secret no box makes"
fi
grep -q 'sneakers-lab-secrets' "$work/refused.log" || fail "the refusal doesn't name the Secret: $(tail -2 "$work/refused.log")"
echo "ok: refused a non-empty OUT and a Secret no box makes"
