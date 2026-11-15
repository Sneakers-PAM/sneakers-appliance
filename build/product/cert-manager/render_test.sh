#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# render.sh's cert-manager stack: the upstream manifest is taken only at the
# checksum recorded for the pinned version, every cert-manager image runs by
# the digest release.yaml pins and is never pulled, the controller starts
# its solver pods from the pinned acmesolver, and a pin without a recorded
# checksum, an upstream that changed, and a pin missing from release.yaml
# are each refused. It runs offline over a small stand-in upstream.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# Stand-in digests: hex, the shape release.yaml pins.
d_ctl="sha256:$(printf '1%.0s' {1..64})"; d_web="sha256:$(printf '2%.0s' {1..64})"
d_inj="sha256:$(printf '3%.0s' {1..64})"; d_sol="sha256:$(printf '4%.0s' {1..64})"

mkrelease() { # mkrelease FILE [nosolver]
  {
cat <<E2
spec:
  thirdParty:
    postgres:
      image: docker.io/library/postgres
      version: "17"
      digest: sha256:$(printf '9%.0s' {1..64})
  platform:
    traefik:
      image: docker.io/library/traefik
      version: v3.7.14
      digest: sha256:$(printf '5%.0s' {1..64})
    cert-manager-controller:
      image: quay.io/jetstack/cert-manager-controller
      version: v1.21.2
      digest: $d_ctl
    cert-manager-webhook:
      image: quay.io/jetstack/cert-manager-webhook
      version: v1.21.2
      digest: $d_web
    cert-manager-cainjector:
      image: quay.io/jetstack/cert-manager-cainjector
      version: v1.21.2
      digest: $d_inj
E2
    if [ "${2:-}" != nosolver ]; then
cat <<E2
    # The controller starts one of these for every HTTP-01 challenge.
    cert-manager-acmesolver:
      image: quay.io/jetstack/cert-manager-acmesolver
      version: v1.21.2
      digest: $d_sol
E2
    fi
cat <<E2
  jobs:
    migrate:
      image: ghcr.io/sneakers-pam/sneakers-migrate
      digest: sha256:$(printf '6%.0s' {1..64})
E2
  } > "$1"
}
mkrelease "$work/release.yaml"
mkrelease "$work/release-no-solver.yaml" nosolver

cat > "$work/upstream.yaml" <<'E2'
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-manager-cainjector
spec:
  template:
    spec:
      containers:
        - name: cert-manager-cainjector
          image: "quay.io/jetstack/cert-manager-cainjector:v1.21.2"
          imagePullPolicy: IfNotPresent
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-manager
spec:
  template:
    spec:
      containers:
        - name: cert-manager-controller
          image: "quay.io/jetstack/cert-manager-controller:v1.21.2"
          imagePullPolicy: IfNotPresent
          args:
          - --v=2
          - --acme-http01-solver-image=quay.io/jetstack/cert-manager-acmesolver:v1.21.2
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-manager-webhook
spec:
  template:
    spec:
      containers:
        - name: cert-manager-webhook
          image: "quay.io/jetstack/cert-manager-webhook:v1.21.2"
          imagePullPolicy: IfNotPresent
E2
sum="$(sha256sum "$work/upstream.yaml" | cut -d' ' -f1)"
printf 'v1.21.2 %s\n' "$sum" > "$work/sums"

run() { RELEASE="$work/release.yaml" UPSTREAM="$work/upstream.yaml" SUMS="$work/sums" OUT="$1" bash "$here/render.sh"; }

out="$work/out"
run "$out" >/dev/null || fail "render failed"
f="$out/cert-manager/cert-manager.yaml"
[ -s "$f" ] || fail "no stack at $f"
for want in "cert-manager-controller@$d_ctl" "cert-manager-webhook@$d_web" "cert-manager-cainjector@$d_inj" "--acme-http01-solver-image=quay.io/jetstack/cert-manager-acmesolver@$d_sol"; do
  grep -qF -- "$want" "$f" || fail "the stack doesn't carry $want"
done
if grep -E 'quay.io/jetstack/[a-z-]+:v' "$f"; then fail "an image is still named by tag"; fi
if grep -q 'IfNotPresent\|imagePullPolicy: Always' "$f"; then fail "an image may still be pulled"; fi
[ "$(grep -c 'imagePullPolicy: Never' "$f")" = 3 ] || fail "every container must never pull"

# A changed upstream is refused.
echo "# changed" >> "$work/upstream.yaml"
if run "$work/out2" 2>"$work/err"; then fail "a changed upstream was accepted"; fi
grep -q 'checksum' "$work/err" || fail "the refusal doesn't say checksum: $(cat "$work/err")"
sed -i.bak '$d' "$work/upstream.yaml" && rm "$work/upstream.yaml.bak"

# A pin without a recorded checksum is refused.
printf 'v1.20.0 %s\n' "$sum" > "$work/sums"
if run "$work/out3" 2>"$work/err"; then fail "a pin with no recorded checksum was accepted"; fi
grep -q 'v1.21.2' "$work/err" || fail "the refusal doesn't name the pin: $(cat "$work/err")"
printf 'v1.21.2 %s\n' "$sum" > "$work/sums"

# A release.yaml without the acmesolver is refused.
if RELEASE="$work/release-no-solver.yaml" UPSTREAM="$work/upstream.yaml" SUMS="$work/sums" OUT="$work/out4" bash "$here/render.sh" 2>"$work/err"; then fail "a release without the acmesolver pin was accepted"; fi
grep -q 'acmesolver' "$work/err" || fail "the refusal doesn't name the acmesolver: $(cat "$work/err")"

# A stack folder that has something in it is refused, other stacks beside it aren't.
mkdir -p "$work/full/cert-manager" "$work/other/edge" && touch "$work/full/cert-manager/x" "$work/other/edge/edge.yaml"
run "$work/other" >/dev/null || fail "another stack beside it was refused"
if run "$work/full" 2>/dev/null; then fail "a non-empty OUT was accepted"; fi
echo "render_test: ok"
