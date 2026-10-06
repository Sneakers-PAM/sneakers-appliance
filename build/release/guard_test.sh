#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# guard.sh passes a v tag on main's history and a lab dispatch, and refuses a
# tag off main, a malformed tag, and a production tag without the committed
# production key record or the sneakers-release pin. It runs in this
# repository's own history: the merge base with origin/main is on main, and
# a branch commit ahead of it isn't. Needs a full clone (fetch-depth 0).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
main_ref="${MAIN_REF:-origin/main}"
on_main="$(git -C "$root" rev-parse "$main_ref")"
off_main="$(git -C "$root" rev-parse HEAD)"
echo "PK 00" > "$work/fingerprints.txt"
echo "SNEAKERS_RELEASE_VERSION=0.1.0" > "$work/pins.env"

guard() { # event ref sha [input]
  ( cd "$root" && EVENT="$1" REF_NAME="$2" COMMIT="$3" INPUT_VERSION="${4:-}" MAIN_REF="$main_ref" \
    FINGERPRINTS="$work/fingerprints.txt" PINS_ENV="$work/pins.env" GITHUB_OUTPUT="$work/out" \
    bash "$here/guard.sh" )
}
expect_ok() { : > "$work/out"; guard "$@" >/dev/null 2>&1 || { echo "FAIL: refused: $*" >&2; exit 1; }; }
expect_refused() { # message args...
  local msg="$1"; shift
  if out="$(guard "$@" 2>&1)"; then echo "FAIL: passed: $*" >&2; exit 1; fi
  grep -q "$msg" <<<"$out" || { echo "FAIL: $* said: $out" >&2; exit 1; }
}

expect_ok push v0.1.0 "$on_main"
grep -qx "version=0.1.0" "$work/out" && grep -qx "channel=production" "$work/out" || { echo "FAIL: outputs: $(cat "$work/out")" >&2; exit 1; }
expect_ok push v0.1.0-rc.1 "$on_main"
expect_ok workflow_dispatch main "$off_main" 0.0.1
grep -qx "channel=lab" "$work/out" || { echo "FAIL: lab outputs: $(cat "$work/out")" >&2; exit 1; }

if [ "$off_main" != "$on_main" ] && ! git -C "$root" merge-base --is-ancestor "$off_main" "$main_ref"; then
  expect_refused "isn't on main" push v0.1.0 "$off_main"
else
  echo "guard_test: HEAD is on main; the off-main case needs a branch commit (skipped)"
fi
expect_refused "isn't a release tag" push v0.1 "$on_main"
expect_refused "isn't a release tag" push release-1 "$on_main"
expect_refused "isn't a lab version" workflow_dispatch main "$on_main" '0.0.1;x'
rm "$work/fingerprints.txt"
expect_refused "fingerprints.txt" push v0.1.0 "$on_main"
echo "PK 00" > "$work/fingerprints.txt"
echo "SNEAKERS_RELEASE_VERSION=" > "$work/pins.env"
expect_refused "SNEAKERS_RELEASE_VERSION" push v0.1.0 "$on_main"
echo "PASS: guard"
