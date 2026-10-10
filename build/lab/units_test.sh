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

# Every other file the bundle is built from (build/product/build.sh) moves
# the product digest too: product.yaml, the import Job's template and the
# brand, each on its own, and none of them moves another unit's.
mkdir -p "$work/brand"
echo 'format: 2' > "$work/product.yaml"
echo 'kind: Job' > "$work/import-job.yaml"
echo 'name: Lab' > "$work/brand/brand.yaml"
full() { RELEASE="$work/release.yaml" STACKS="$work/stacks" PRODUCT_YAML="$work/product.yaml" IMPORT_JOB="$work/import-job.yaml" BRAND="$work/brand" bash "$here/units.sh" inputs product; }
o2="$(os)" w2="$(web)" f1="$(full)"
hex "$f1" product
[ "$f1" = "$(full)" ] || { echo "FAIL: the full product digest isn't stable" >&2; exit 1; }
[ "$f1" != "$(product)" ] || { echo "FAIL: product.yaml, the import Job and the brand didn't count" >&2; exit 1; }
moved() { # what file
  local before
  before="$(full)"
  echo "changed" >> "$2"
  [ "$(full)" != "$before" ] || { echo "FAIL: a changed $1 didn't change the product digest" >&2; exit 1; }
  [ "$(os)" = "$o2" ] && [ "$(web)" = "$w2" ] || { echo "FAIL: a changed $1 moved another unit's digest" >&2; exit 1; }
}
moved product.yaml "$work/product.yaml"
moved "import Job" "$work/import-job.yaml"
moved brand "$work/brand/brand.yaml"
echo 'logo' > "$work/brand/logo.svg"
[ "$(full)" != "$f1" ] || { echo "FAIL: a new brand file didn't change the product digest" >&2; exit 1; }
# The same bytes under another role are another input: product.yaml's
# content as the import Job isn't the same bundle.
cp "$work/product.yaml" "$work/swap.yaml"
a="$(RELEASE="$work/release.yaml" STACKS="$work/stacks" PRODUCT_YAML="$work/swap.yaml" bash "$here/units.sh" inputs product)"
b="$(RELEASE="$work/release.yaml" STACKS="$work/stacks" PRODUCT_YAML="$work/release.yaml" IMPORT_JOB="$work/swap.yaml" bash "$here/units.sh" inputs product)"
[ "$a" != "$b" ] || { echo "FAIL: a file's role doesn't count" >&2; exit 1; }
# The lab build's own product.yaml counts by default, with the lab stacks.
lab1="$(RELEASE="$work/release.yaml" bash "$here/units.sh" inputs product)"
lab2="$(RELEASE="$work/release.yaml" PRODUCT_YAML="$work/product.yaml" bash "$here/units.sh" inputs product)"
[ "$lab1" != "$lab2" ] || { echo "FAIL: the lab product.yaml isn't the default" >&2; exit 1; }
# A named file that isn't there is refused, never left out.
if RELEASE="$work/release.yaml" STACKS="$work/stacks" PRODUCT_YAML="$work/nothing.yaml" bash "$here/units.sh" inputs product >/dev/null 2>&1; then
  echo "FAIL: a missing product.yaml passed" >&2; exit 1
fi

if bash "$here/units.sh" inputs nothing >/dev/null 2>&1; then echo "FAIL: an unknown unit passed" >&2; exit 1; fi
if bash "$here/units.sh" >/dev/null 2>&1; then echo "FAIL: no OUT passed" >&2; exit 1; fi

# The release job seals the production units with the same script: it
# names the channel and the commit, and brings the Base OS digest its build
# job computed. Each is refused, before anything is built, when it's wrong.
mkdir -p "$work/out"
echo 0.1.0 > "$work/out/version"
refused() { # message env...
  local msg="$1"; shift
  if out="$(env "$@" OUT="$work/out" KEYS="$work/keys" bash "$here/units.sh" 2>&1)"; then echo "FAIL: passed: $*" >&2; exit 1; fi
  grep -q "$msg" <<<"$out" || { echo "FAIL: $* said: $out" >&2; exit 1; }
  [ ! -e "$work/out/units" ] && [ ! -e "$work/out/work" ] || { echo "FAIL: $* wrote output before refusing" >&2; exit 1; }
}
refused "CHANNEL is staging" CHANNEL=staging
refused "COMMIT" CHANNEL=production
refused "COMMIT" CHANNEL=production COMMIT=xyz
refused "BASEOS_INPUTS" CHANNEL=production COMMIT=1a2b3c4 BASEOS_INPUTS=nothex
refused "BRIDGE is for lab builds only" CHANNEL=production COMMIT=1a2b3c4 BRIDGE=1
refused "OLD_NAMES is for lab builds only" CHANNEL=production COMMIT=1a2b3c4 OLD_NAMES=1
refused "doesn't end with -g<commit>" CHANNEL=lab

# A Base OS always ships with its Base Web (spec 7, Section 4.4): a build
# without the :8443 pages is refused before anything is sealed.
mkdir -p "$work/nopages"
echo 0.0.0-lab.1-g1a2b3c4 > "$work/nopages/version"
if out="$(OUT="$work/nopages" KEYS="$work/keys" bash "$here/units.sh" 2>&1)"; then echo "FAIL: a build without pages passed" >&2; exit 1; fi
grep -q "a Base OS always ships with its Base Web" <<<"$out" || { echo "FAIL: no pages said: $out" >&2; exit 1; }
[ ! -e "$work/nopages/units" ] && [ ! -e "$work/nopages/work" ] || { echo "FAIL: a build without pages wrote output" >&2; exit 1; }

echo "units: ok"

