#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# units.sh's input digests: each unit's is the same for the same inputs,
# and changes when one of its own inputs does and not when another unit's
# does, so a release job can tell which units changed. The sealing itself
# is covered by sneakers-artifact's tests; it needs a lab build.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/pages/assets" "$work/openssh" "$work/stacks/hello"
echo '<html></html>' > "$work/pages/index.html"
echo 'app' > "$work/pages/assets/app.js"
echo 'kernel' > "$work/bzImage"
echo 'sshd' > "$work/openssh/sshd"
echo 'apiVersion: v1' > "$work/stacks/hello/a.yaml"
echo 'k0s: pinned' > "$work/release.yaml"

os() { KERNEL="$work/bzImage" OPENSSH="$work/openssh" bash "$here/units.sh" inputs baseOS; }
web() { PAGES="$work/pages" bash "$here/units.sh" inputs baseWeb; }
product() { RELEASE="$work/release.yaml" STACKS="$work/stacks" bash "$here/units.sh" inputs product; }
hex() { [[ "$1" =~ ^[0-9a-f]{64}$ ]] || { echo "FAIL: $2 isn't a SHA-256: $1" >&2; exit 1; }; }

o1="$(os)" w1="$(web)" p1="$(product)"
hex "$o1" baseOS; hex "$w1" baseWeb; hex "$p1" product
[ "$o1" = "$(os)" ] && [ "$w1" = "$(web)" ] && [ "$p1" = "$(product)" ] || { echo "FAIL: a digest isn't stable" >&2; exit 1; }

echo 'app 2' > "$work/pages/assets/app.js"
[ "$(web)" != "$w1" ] || { echo "FAIL: a changed page didn't change the Base Web digest" >&2; exit 1; }
[ "$(os)" = "$o1" ] && [ "$(product)" = "$p1" ] || { echo "FAIL: a page change moved another unit's digest" >&2; exit 1; }

echo 'kernel 2' > "$work/bzImage"
[ "$(os)" != "$o1" ] || { echo "FAIL: a new kernel didn't change the Base OS digest" >&2; exit 1; }

echo 'image: sha256:2' >> "$work/release.yaml"
[ "$(product)" != "$p1" ] || { echo "FAIL: a new image digest didn't change the product digest" >&2; exit 1; }

if bash "$here/units.sh" inputs nothing >/dev/null 2>&1; then echo "FAIL: an unknown unit passed" >&2; exit 1; fi
if bash "$here/units.sh" >/dev/null 2>&1; then echo "FAIL: no OUT passed" >&2; exit 1; fi
echo "units: ok"
