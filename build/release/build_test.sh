#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh refuses, before it fetches or builds anything, without the pinned
# release.yaml and the sneakers-web checkout, and on a release.yaml that
# pins an image by a placeholder instead of a digest, and says why.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/web"
cat > "$work/release.yaml" <<'YAML'
apiVersion: sneakers-pam/v1alpha1
kind: Release
spec:
  services:
    vault:
      image: ghcr.io/sneakers-pam/sneakers-vault
      digest: sha256:TBD-at-release
YAML

build() { # env...
  env "$@" VERSION=0.1.0 KERNEL=x KERNELRELEASE=x VERITYSETUP=x OPENSSH=x BUSYBOX=x STATIC=x OUT="$work/out" \
    bash "$here/build.sh" 2>&1
}
refused() { # message env...
  local msg="$1" out
  shift
  if out="$(build "$@")"; then echo "FAIL: built with $*" >&2; exit 1; fi
  grep -q "$msg" <<<"$out" || { echo "FAIL: $* said: $out" >&2; exit 1; }
  [ ! -e "$work/out" ] || { echo "FAIL: $* wrote $work/out before refusing" >&2; exit 1; }
}
refused "RELEASE" -u RELEASE WEB="$work/web"
refused "WEB" -u WEB RELEASE="$work/release.yaml"
refused "services.vault" RELEASE="$work/release.yaml" WEB="$work/web"
echo "ok: refused without the pinned sources and on a placeholder digest"
