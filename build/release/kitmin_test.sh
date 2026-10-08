#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The kit floor (spec.kitMin) is pinned once, as KIT_MIN in pins.env, and
# both release paths pass it on: the production assemble with --kit-min and
# the lab job to build/lab/build.sh (docs/kit.md).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
wf="$root/.github/workflows/release.yml"
fail() { echo "FAIL: $*" >&2; exit 1; }

kit_min="$(sed -n 's/^KIT_MIN=//p' "$here/pins.env")"
[ -n "$kit_min" ] || fail "pins.env doesn't set KIT_MIN"
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
[[ "$kit_min" =~ $semver ]] || fail "KIT_MIN=$kit_min isn't a semantic version"

# step <name>: the lines of release.yml's step called name, up to the next step.
step() {
  awk -v name="$1" '
    $0 ~ "^ *- name: " { on = (index($0, "- name: " name) > 0) }
    on { print }
  ' "$wf"
}

assemble="$(step "Assemble the artifact")"
[ -n "$assemble" ] || fail "release.yml has no Assemble the artifact step"
grep -q 'source build/release/pins.env' <<<"$assemble" || fail "the assemble step doesn't read build/release/pins.env"
grep -q -- '--kit-min "\$KIT_MIN"' <<<"$assemble" || fail "the production assemble doesn't pass --kit-min \"\$KIT_MIN\""

lab="$(step "Build a lab release and its .bin")"
[ -n "$lab" ] || fail "release.yml has no lab build step"
grep -q 'source build/release/pins.env' <<<"$lab" || fail "the lab step doesn't read build/release/pins.env"
grep -q 'KIT_MIN="\$KIT_MIN"' <<<"$lab" || fail "the lab step doesn't pass KIT_MIN to build/lab/build.sh"

echo "kitmin_test: ok (KIT_MIN=$kit_min)"
