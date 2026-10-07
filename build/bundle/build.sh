#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh: build the airgap image bundle for the root image (spec 1
# Section 3.4). For every image release.yaml pins, the org release-key
# signature of the pinned digest is checked first, then the image is pulled
# by that digest for the architecture and written as a reproducible OCI
# archive, <hex>.tar, with the signature beside it as <hex>.tar.sigstore.json.
# The finished bundle is checked against release.yaml in both directions.
# Any refusal (a placeholder digest, a missing or foreign signature, an image
# with no build for the architecture) leaves OUT empty.
#
# Inputs (environment):
#   RELEASE      release.yaml (from sneakers-release)
#   RELEASE_KEY  the org release key (cosign.pub) the images are signed with
#   SIGNATURES   directory of the org signatures, <hex>.sigstore.json per
#                pinned digest (the sneakers-release countersignatures)
#   ARCH         amd64 (default) or arm64
#   OUT          the bundle directory (empty or missing); pass it to
#                build/root/build.sh as IMAGES
#   PLAIN_HTTP   1 to talk to a lab registry without TLS
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${RELEASE:?}" "${RELEASE_KEY:?}" "${SIGNATURES:?}" "${OUT:?}"
arch="${ARCH:-amd64}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
plain=()
[ "${PLAIN_HTTP:-}" != 1 ] || plain=(--plain-http)

tool="$(mktemp -d)"
trap 'rm -rf "$tool"' EXIT
CGO_ENABLED=0 go build -trimpath -o "$tool/bundle" "$root/build/tools/bundle"
"$tool/bundle" pull --release "$RELEASE" --key "$RELEASE_KEY" --signatures "$SIGNATURES" --arch "$arch" --out "$OUT" "${plain[@]}"
"$tool/bundle" check --release "$RELEASE" --key "$RELEASE_KEY" --out "$OUT"
echo "bundle: $(find "$OUT" -name '*.tar' | wc -l) images for $arch in $OUT ($(du -sb "$OUT" | cut -f1) bytes)"
