#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# pages.sh: build the :8443 static pages (sneakers-web apps/appliance-admin)
# from a sneakers-web checkout and copy them to OUT, for the root's
# OSADMIN_ASSETS. The build is stamped with APP_VERSION (the release's
# version) and APP_COMMIT (the checkout's commit), which the appliance
# admin's About and diagnostics report; without them its Vite config falls
# back to 0.0.0 and "unknown". Pages that come out without the stamp are
# refused.
#
# Inputs (environment):
#   WEB      a sneakers-web checkout at the commit to ship
#   VERSION  the release version, with its build number
#   OUT      the output directory (replaced)
set -euo pipefail
: "${WEB:?}" "${VERSION:?}" "${OUT:?}"
commit="$(git -C "$WEB" rev-parse --short=7 HEAD)"
echo "pages: sneakers-web $commit, version $VERSION"
(
  cd "$WEB"
  npm ci --ignore-scripts
  APP_VERSION="$VERSION" APP_COMMIT="$commit" npm run build -w @sneakers-web/appliance-admin
)
client="$WEB/apps/appliance-admin/build/client"
[ -f "$client/index.html" ] || { echo "pages: $client/index.html is missing" >&2; exit 1; }
# The minifier may quote a string literal with ", ' or a backtick.
for stamp in "$VERSION" "$commit"; do
  grep -rqF -e "\"$stamp\"" -e "'$stamp'" -e "\`$stamp\`" "$client/assets" ||
    { echo "pages: the build is not stamped with $stamp" >&2; exit 1; }
done
rm -rf "$OUT"
mkdir -p "$OUT"
cp -r "$client/." "$OUT/"
echo "pages: $(find "$OUT" -type f | wc -l) files"
