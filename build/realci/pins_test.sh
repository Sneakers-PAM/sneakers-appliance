#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The real-bundle job's pins (build/realci/pins.env) are full commits, the
# appliance ones in this repository's history; the release workflow builds
# nothing until the job passes; and a merge never cancels the job running
# on main.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }
# shellcheck source=build/realci/pins.env
source "$here/pins.env"
for v in OLD_BASE_COMMIT P12_APPLIANCE_COMMIT P13_APPLIANCE_COMMIT CONTROL_COMMIT P12_RELEASE_COMMIT P13_RELEASE_COMMIT NEXT_RELEASE_COMMIT; do
  c="${!v}"
  if [ "$v" = NEXT_RELEASE_COMMIT ] && [ -z "$c" ]; then continue; fi
  [[ "$c" =~ ^[0-9a-f]{40}$ ]] || { bad "$v is '$c', not a full commit"; continue; }
  case "$v" in
    *RELEASE*) ;;
    *) git -C "$root" cat-file -e "$c^{commit}" 2>/dev/null || bad "$v $c isn't in this repository's history" ;;
  esac
done
wf="$root/.github/workflows/release.yml"
grep -qE '^  realbundles:$' "$wf" || bad "release.yml has no realbundles job"
grep -qF 'uses: ./.github/workflows/real-bundle.yml' "$wf" || bad "release.yml's realbundles job doesn't call real-bundle.yml"
sed -n '/^  images:$/,/^    if:/p' "$wf" | grep -qE '^    needs: \[guard, realbundles\]$' || bad "release.yml's images job doesn't wait for the real bundles"
line="$(grep -E '^[[:space:]]+cancel-in-progress:' "$root/.github/workflows/real-bundle.yml" | head -1 | sed -E 's/^[[:space:]]+cancel-in-progress:[[:space:]]*//')"
[ "$line" = "\${{ github.event_name == 'pull_request' }}" ] || bad "real-bundle.yml cancel-in-progress is '$line'; a merge would cancel the job running on main"
[ "$fail" = 0 ] && echo "ok: the real-bundle pins are full commits, the release waits for the job, and main's run is never cancelled"
exit "$fail"
