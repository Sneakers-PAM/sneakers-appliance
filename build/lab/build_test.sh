#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh takes its :8443 pages only from WEB, through pages.sh, which
# stamps them and refuses them unstamped. Pages built elsewhere are refused,
# and so is a build with no pages at all unless NO_PAGES=1 says it's for a
# test that doesn't need them. An existing key set stands in for the rest of
# the build: lab-keys.sh refuses it, the first thing past these checks.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/keys"
touch "$work/keys/cosign.key"

run() { # env assignments
  env -u WEB -u OSADMIN_ASSETS -u NO_PAGES KERNEL=x KERNELRELEASE=x VERITYSETUP=x OPENSSH=x BUSYBOX=x STATIC=x \
    KEYS="$work/keys" OUT="$work/out" "$@" bash "$here/build.sh" 2>&1
}
refused() { # want env assignments
  local want="$1" out
  shift
  if out="$(run "$@")"; then echo "FAIL: $* built" >&2; exit 1; fi
  grep -qF "$want" <<<"$out" || { echo "FAIL: $* said: $out" >&2; exit 1; }
  grep -q 'lab: keys' <<<"$out" && { echo "FAIL: $* got past the page checks: $out" >&2; exit 1; }
  return 0
}
passes() { # env assignments
  local out
  out="$(run "$@")" || true
  grep -q 'lab: keys' <<<"$out" || { echo "FAIL: $* stopped at the page checks: $out" >&2; exit 1; }
}

refused "OSADMIN_ASSETS" OSADMIN_ASSETS="$work/pages"
refused "OSADMIN_ASSETS" OSADMIN_ASSETS="$work/pages" WEB="$work/web"
refused "OSADMIN_ASSETS" OSADMIN_ASSETS="$work/pages" NO_PAGES=1
refused "set WEB"
refused "NO_PAGES" WEB="$work/web" NO_PAGES=1
passes WEB="$work/web"
passes NO_PAGES=1
echo "lab build pages: ok"
