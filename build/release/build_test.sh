#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh refuses, before it fetches or builds anything, without the image
# countersignatures the airgap bundle needs, and says why.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
if out="$(env -u SIGNATURES VERSION=0.1.0 KERNEL=x KERNELRELEASE=x VERITYSETUP=x OPENSSH=x BUSYBOX=x OUT="$work/out" \
  bash "$here/build.sh" 2>&1)"; then
  echo "FAIL: built without SIGNATURES" >&2; exit 1
fi
grep -q "SIGNATURES: sneakers-release publishes no image countersignatures yet" <<<"$out" || { echo "FAIL: said: $out" >&2; exit 1; }
[ ! -e "$work/out" ] || { echo "FAIL: wrote $work/out before refusing" >&2; exit 1; }
echo "ok: refused without the image countersignatures"
