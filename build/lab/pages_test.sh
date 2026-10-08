#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# pages.sh builds the :8443 pages from a sneakers-web checkout with
# APP_VERSION set to the release version and APP_COMMIT to the checkout's
# commit, the stamp the appliance admin's About and diagnostics show, and
# refuses pages that come out without it. npm is a stand-in that writes
# what the real build would: index.html and a bundle carrying the stamp.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

web="$work/web"
mkdir -p "$work/bin"
# Any checkout stands in for sneakers-web; this repository's is at hand.
git clone -q --shared --no-checkout "$root" "$web"
commit="$(git -C "$web" rev-parse --short=7 HEAD)"

fake_npm() { # stamp: yes or no
  cat > "$work/bin/npm" <<SH
#!/usr/bin/env bash
set -euo pipefail
echo "\$*" >> "$work/npm.log"
case "\$1" in
  ci) [ "\$2" = --ignore-scripts ] || { echo "npm ci without --ignore-scripts" >&2; exit 1; } ;;
  run)
    client=apps/appliance-admin/build/client
    mkdir -p "\$client/assets"
    echo '<!doctype html>' > "\$client/index.html"
    if [ "$1" = yes ]; then
      printf 'const v="%s",c="%s";\n' "\$APP_VERSION" "\$APP_COMMIT" > "\$client/assets/root.js"
    else
      printf 'const v="0.0.0",c="unknown";\n' > "\$client/assets/root.js"
    fi
    ;;
esac
SH
  chmod +x "$work/bin/npm"
}

run() { PATH="$work/bin:$PATH" WEB="$web" VERSION=0.0.1-lab.1-gabc1234 OUT="$work/out" bash "$here/pages.sh"; }

fake_npm yes
run >/dev/null
grep -q '^ci --ignore-scripts$' "$work/npm.log" || { echo "FAIL: npm ci --ignore-scripts not run: $(cat "$work/npm.log")" >&2; exit 1; }
grep -q '^run build -w @sneakers-web/appliance-admin$' "$work/npm.log" || { echo "FAIL: the appliance admin build not run: $(cat "$work/npm.log")" >&2; exit 1; }
[ -f "$work/out/index.html" ] || { echo "FAIL: no index.html in OUT" >&2; exit 1; }
grep -qF '"0.0.1-lab.1-gabc1234"' "$work/out/assets/root.js" || { echo "FAIL: version not stamped: $(cat "$work/out/assets/root.js")" >&2; exit 1; }
grep -qF "\"$commit\"" "$work/out/assets/root.js" || { echo "FAIL: commit not stamped: $(cat "$work/out/assets/root.js")" >&2; exit 1; }

fake_npm no
rm -rf "$work/out"
if out="$(run 2>&1)"; then echo "FAIL: unstamped pages passed" >&2; exit 1; fi
grep -q "not stamped" <<<"$out" || { echo "FAIL: unstamped pages said: $out" >&2; exit 1; }
[ ! -e "$work/out" ] || { echo "FAIL: unstamped pages were copied to OUT" >&2; exit 1; }

if PATH="$work/bin:$PATH" VERSION=0.0.1 OUT="$work/out" bash "$here/pages.sh" >/dev/null 2>&1; then
  echo "FAIL: no WEB passed" >&2; exit 1
fi
echo "pages: ok"
