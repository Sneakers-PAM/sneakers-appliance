#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# images.sh builds only linux/amd64 or linux/arm64, and refuses any other
# PLATFORM before it fetches or builds anything. release.yml builds each
# architecture on a runner of that architecture (no emulation) and joins
# the two builds into one index per service before anything fills,
# countersigns or pushes them.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
wf="${WF:-$root/.github/workflows/release.yml}"
fail() { echo "FAIL: $*" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if out="$(RELEASE="$work/release.yaml" OUT="$work/out" PLATFORM=linux/s390x bash "$here/images.sh" 2>&1)"; then
  fail "images.sh built for linux/s390x"
fi
grep -q "PLATFORM linux/s390x" <<<"$out" || fail "images.sh said: $out"
[ ! -e "$work/out" ] || fail "images.sh wrote $work/out before refusing"

# job <id>: the lines of the job called id, up to the next job.
job() { awk -v id="  $1:" '$0 == id { on = 1; next } on && /^  [A-Za-z_][A-Za-z0-9_-]*:$/ { exit } on' "$wf"; }
images="$(job images)"
grep -q "runs-on: \${{ matrix.runner }}" <<<"$images" || fail "the images job doesn't run on its matrix runner"
grep -qE "arch: amd64, runner: ubuntu-24.04 *}" <<<"$images" || fail "the images job doesn't build amd64 on ubuntu-24.04"
grep -qE "arch: arm64, runner: ubuntu-24.04-arm *}" <<<"$images" || fail "the images job doesn't build arm64 on ubuntu-24.04-arm"
grep -q "PLATFORM: linux/\${{ matrix.arch }}" <<<"$images" || fail "the images job doesn't pass its architecture to images.sh"
if grep -qiE "qemu|setup-qemu|binfmt" <<<"$images"; then fail "the images job sets up emulation"; fi
build="$(job build)"
grep -q "bundle index" <<<"$build" || fail "the build job doesn't join the architectures (bundle index)"
for a in amd64 arm64; do
  grep -q "service-images-$a-native" <<<"$build" || fail "the build job doesn't take the $a images"
done
echo "PASS: images"
