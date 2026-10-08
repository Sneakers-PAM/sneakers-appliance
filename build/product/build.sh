#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh: build the product bundle (docs/release.md#the-product-bundle):
# k0s, its airgapped system images and the product images, and the stacks
# k0s applies, unpacked into OUT/tree and checked the way the box checks
# one, then encrypted to the channel's update key with the header to sign
# (bin-pack). It holds no signing key: the caller signs OUT/bin/header.json
# with the release key and runs `sneakers-artifact bin-seal`.
#
# Inputs (environment):
#   VERSION      the product version (the release's)
#   ARCH         amd64 (default) or arm64
#   CHANNEL      production or lab
#   BASES        the base versions the bundle fits, space-separated
#   RELEASE      release.yaml (k0s's pin and the images)
#   RELEASE_KEY  the release key (cosign.pub) the images are signed with
#   SIGNATURES   directory of the image signatures, <hex>.sigstore.json
#   K0S          the k0s binary, checked against release.yaml's pin
#   RECIPIENT    the channel's update key recipient (update.pub)
#   STACKS       a directory of stacks, <stack>/*.yaml (optional)
#   PLAIN_HTTP   1 to talk to a lab registry without TLS
#   OUT          the output directory: tree/ (the unpacked bundle) and
#                bin/header.json, bin/payload.age
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${VERSION:?}" "${CHANNEL:?}" "${BASES:?}" "${RELEASE:?}" "${RELEASE_KEY:?}" "${SIGNATURES:?}" "${K0S:?}" "${RECIPIENT:?}" "${OUT:?}"
arch="${ARCH:-amd64}"

want="$(go run "$root/build/tools/k0spin" "$RELEASE" "$arch")"
got="$(sha256sum "$K0S" | cut -d' ' -f1)"
[ "$want" = "$got" ] || { echo "product: $K0S has SHA-256 $got; release.yaml pins $want" >&2; exit 1; }

tree="$OUT/tree"
rm -rf "$tree" "$OUT/bin"
mkdir -p "$tree"
install -m 0644 "$RELEASE" "$tree/release.yaml"
install -m 0755 "$K0S" "$tree/k0s"

echo "product: images ($arch)"
RELEASE="$RELEASE" RELEASE_KEY="$RELEASE_KEY" SIGNATURES="$SIGNATURES" ARCH="$arch" OUT="$tree/images" PLAIN_HTTP="${PLAIN_HTTP:-}" \
  bash "$root/build/bundle/build.sh"

if [ -n "${STACKS:-}" ]; then
  for d in "$STACKS"/*/; do
    stack="$(basename "$d")"
    mkdir -p "$tree/manifests/$stack"
    install -m 0644 "$d"*.yaml "$tree/manifests/$stack/"
    echo "product: stack $stack"
  done
fi

tool="$(mktemp -d)"
trap 'rm -rf "$tool"' EXIT
CGO_ENABLED=0 go build -trimpath -o "$tool/sneakers-artifact" "$root/cmd/sneakers-artifact"
"$tool/sneakers-artifact" product-check --dir "$tree" --release-key "$RELEASE_KEY" --arch "$arch"

base_flags=()
for b in $BASES; do base_flags+=(--base "$b"); done
"$tool/sneakers-artifact" bin-pack --layout "$tree" --recipient "$RECIPIENT" --version "$VERSION" --arch "$arch" \
  --channel "$CHANNEL" --kind product "${base_flags[@]}" --out "$OUT/bin" >/dev/null
echo "product: $VERSION ($arch, $CHANNEL) for bases $BASES: $(du -sb "$tree" | cut -f1) bytes unpacked, $(stat -c %s "$OUT/bin/payload.age") bytes encrypted"
