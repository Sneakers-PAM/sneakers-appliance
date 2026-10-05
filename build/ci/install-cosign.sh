#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# install-cosign.sh <bindir>: install the pinned cosign release binary,
# checked against the SHA-256 in build/ci/versions.env.
set -euo pipefail
bindir="${1:?usage: install-cosign.sh <bindir>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=build/ci/versions.env
source "$here/versions.env"
mkdir -p "$bindir"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -sSfL -o "$tmp" "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
echo "${COSIGN_SHA256_LINUX_AMD64}  $tmp" | sha256sum -c --quiet
install -m 0755 "$tmp" "$bindir/cosign"
"$bindir/cosign" version >/dev/null
