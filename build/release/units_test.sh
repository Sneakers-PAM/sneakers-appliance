#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The production path ships the three update units the lab does, made by the
# same build/lab/units.sh with the production channel: the build job checks
# out sneakers-release and sneakers-web at the commits the guard read from
# pins.env; the sign job countersigns release.yaml and every pinned image,
# builds the product bundle and seals the units; publish attaches the units,
# their .inputs, the index and the countersignatures to the tag's Release.
# Nothing builds the single .bin from before the units.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
wf="${WF:-$root/.github/workflows/release.yml}"
fail() { echo "FAIL: $*" >&2; exit 1; }
job() { awk -v id="  $1:" '$0 == id { on = 1; next } on && /^  [A-Za-z_][A-Za-z0-9_-]*:$/ { exit } on' "$wf"; }
# has <job> <pattern> <what>: a line of the job, with its continuation
# lines joined, matches.
has() {
  local text
  text="$(job "$1" | sed -e ':a' -e '/\\$/N; s/\\\n *//; ta')"
  grep -qE -- "$2" <<<"$text" || fail "the $1 job doesn't $3"
}

for o in release_repo release_commit web_repo web_commit; do
  has guard "^      $o: \\$\\{\\{ steps.guard.outputs.$o \\}\\}" "output $o"
done
has build 'repository: \$\{\{ needs.guard.outputs.release_repo \}\}' "check out the pinned sneakers-release"
has build 'ref: \$\{\{ needs.guard.outputs.release_commit \}\}' "check out sneakers-release at the pinned commit"
has build 'repository: \$\{\{ needs.guard.outputs.web_repo \}\}' "check out the pinned sneakers-web"
has build 'ref: \$\{\{ needs.guard.outputs.web_commit \}\}' "check out sneakers-web at the pinned commit"
has build 'bundle images --release' "check the pinned release.yaml before the long build"
has sign 'release\.yaml\.sigstore\.json' "countersign release.yaml"
has sign 'image-sigs' "countersign the pinned images"
has sign 'build/product/build\.sh' "build the product bundle"
has sign 'CHANNEL=production .*build/lab/units\.sh|build/lab/units\.sh.*CHANNEL=production' "seal the units with build/lab/units.sh on the production channel"
has publish 'gh release upload' "attach the files to the Release"
has publish '"\$units"/\*\.bin ' "attach the units"
has publish '\*\.bin\.inputs' "attach each unit's inputs"
has publish 'sneakers-product-index\.json' "attach the index"
has publish 'release\.yaml\.sigstore\.json' "attach the release.yaml countersignature"
has publish 'image-sigs/\*\.sigstore\.json' "attach the image countersignatures"

for id in build sign publish; do
  if job "$id" | grep -qE 'sneakers-appliance-\$VERSION-amd64\.bin|--recipient keys/production/update.pub --version "\$VERSION" --arch amd64 --channel production --out'; then
    fail "the $id job still makes the single .bin from before the units"
  fi
done
echo "PASS: the production units"
