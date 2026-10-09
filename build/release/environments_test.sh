#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# release.yml keeps the keys in their environments: only the sign job names
# production, the lab job names lab, no other job names an environment, and
# the only secrets read (besides GITHUB_TOKEN) are the four production ones,
# all inside the sign job.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
wf="${WF:-$root/.github/workflows/release.yml}"
fail() { echo "FAIL: $*" >&2; exit 1; }

# job <id>: the lines of the job called id, up to the next job.
job() { awk -v id="  $1:" '$0 == id { on = 1; next } on && /^  [A-Za-z_][A-Za-z0-9_-]*:$/ { exit } on' "$wf"; }
jobs="$(awk '/^jobs:/ { on = 1; next } on && /^  [A-Za-z_][A-Za-z0-9_-]*:$/ { sub(/:$/, ""); print $1 }' "$wf")"
[ -n "$jobs" ] || fail "$wf lists no jobs"

for id in $jobs; do
  env="$(job "$id" | sed -n 's/^    environment: *//p')"
  case "$id" in
    sign) [ "$env" = production ] || fail "the sign job's environment is '$env', want production" ;;
    lab) [ "$env" = lab ] || fail "the lab job's environment is '$env', want lab" ;;
    *) [ -z "$env" ] || fail "the $id job names the $env environment" ;;
  esac
  used="$(job "$id" | grep -oE 'secrets\.[A-Z_]+' | sort -u | grep -vx 'secrets.GITHUB_TOKEN' || true)"
  if [ "$id" = sign ]; then
    for s in $used; do
      case "${s#secrets.}" in
        SB_DB_KEY | RELEASE_COSIGN_KEY | RELEASE_COSIGN_PASSWORD | UPDATE_AGE_KEY) ;;
        *) fail "the sign job reads $s, not one of the four production secrets" ;;
      esac
    done
  else
    [ -z "$used" ] || fail "the $id job reads $(tr '\n' ' ' <<<"$used")"
  fi
done
echo "PASS: environments"
