#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The real-bundle job's cache of the old bundles (build/realci/cache.sh):
# its key moves with every pin and input that shapes the old base and the
# .12 and .13 bundles, and with nothing else; a restore refuses a set
# whose sums don't match; and the workflow restores only on the exact key.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# A copy of the working tree, so each case changes one file in it.
(cd "$root" && git ls-files -co --exclude-standard -z | xargs -0 tar -cf - 2>/dev/null) | (mkdir -p "$tmp/src" && tar -xf - -C "$tmp/src")
git -C "$tmp/src" init -q && git -C "$tmp/src" add -A
key() { ROOT="$tmp/src" bash "$tmp/src/build/realci/cache.sh" key; }
base="$(key)"
[[ "$base" =~ ^realci-old-[0-9a-f]{64}$ ]] || bad "the key is '$base', not realci-old-<sha256>"
[ "$(key)" = "$base" ] || bad "two runs on one tree give two keys"

# case <want: moves|stays> <what> <file> <sed expression or "append">
case_() {
  local want="$1" what="$2" file="$3" how="$4" got
  cp -a "$tmp/src/$file" "$tmp/saved"
  if [ "$how" = append ]; then echo "# $what" >> "$tmp/src/$file"; else sed -i "$how" "$tmp/src/$file"; fi
  cmp -s "$tmp/saved" "$tmp/src/$file" && { bad "$what: the edit changed nothing"; return; }
  got="$(key)"
  case "$want" in
    moves) [ "$got" != "$base" ] || bad "$what doesn't change the key" ;;
    stays) [ "$got" = "$base" ] || bad "$what changes the key" ;;
  esac
  cp -a "$tmp/saved" "$tmp/src/$file"
}
case_ moves "the old base pin" build/realci/pins.env 's/^OLD_BASE_COMMIT=.*/OLD_BASE_COMMIT=0000000000000000000000000000000000000000/'
case_ moves "the .12 appliance pin" build/realci/pins.env 's/^P12_APPLIANCE_COMMIT=.*/P12_APPLIANCE_COMMIT=0000000000000000000000000000000000000000/'
case_ moves "the .12 release pin" build/realci/pins.env 's/^P12_RELEASE_COMMIT=.*/P12_RELEASE_COMMIT=0000000000000000000000000000000000000000/'
case_ moves "the .13 appliance pin" build/realci/pins.env 's/^P13_APPLIANCE_COMMIT=.*/P13_APPLIANCE_COMMIT=0000000000000000000000000000000000000000/'
case_ moves "the .13 release pin" build/realci/pins.env 's/^P13_RELEASE_COMMIT=.*/P13_RELEASE_COMMIT=0000000000000000000000000000000000000000/'
case_ stays "the next release pin" build/realci/pins.env 's/^NEXT_RELEASE_COMMIT=.*/NEXT_RELEASE_COMMIT=0000000000000000000000000000000000000000/'
case_ stays "the control pin" build/realci/pins.env 's/^CONTROL_COMMIT=.*/CONTROL_COMMIT=0000000000000000000000000000000000000000/'
case_ moves "build/release/images.sh" build/release/images.sh append
case_ moves "build/realci/build.sh" build/realci/build.sh append
case_ moves "build/realci/product.sh" build/realci/product.sh append
case_ moves "build/realci/cache.sh" build/realci/cache.sh append
case_ moves "the lab hook" build/lab/overlay/usr/libexec/sneakers/lab-hook append
case_ moves "build/ci/versions.env (k0s, helm, cosign, the kernel)" build/ci/versions.env append
case_ moves "the kernel config" os/kernel/config-base append
case_ moves "a static tool's script" build/static/cryptsetup.sh append
case_ moves "the busybox config" build/busybox/busybox.config append
case_ moves "a package sneakers-artifact seals with" "$(cd "$root" && git ls-files 'internal/artifact/*.go' | grep -v _test.go | head -1)" '$a // changed'
case_ moves "go.mod" go.mod '$a // changed'
mkdir -p "$tmp/src/build/busybox/work" && echo left > "$tmp/src/build/busybox/work/obj"
[ "$(key)" = "$base" ] || bad "an untracked build leftover changes the key"
mv "$tmp/src/build/busybox/work" "$tmp/leftover"
case_ stays "the real-bundle test" test/image/k0s/realbundle_test.go append
case_ stays "docs/testing.md" docs/testing.md append
case_ stays "a package sneakers-artifact doesn't import" "$(cd "$root" && git ls-files 'cmd/sneakers-kit/*.go' | grep -v _test.go | head -1)" '$a // changed'

# A runner whose build tools differ builds a different old base.
got="$(ROOT="$tmp/src" REALCI_TOOL_VERSIONS="systemd-boot-efi 0" bash "$tmp/src/build/realci/cache.sh" key)"
[ "$got" != "$base" ] || bad "the runner's build tool versions don't change the key"

# A restore checks the sums before it uses anything.
set_dir="$tmp/set"
mkdir -p "$set_dir/base-old"
echo 0.0.6-test > "$set_dir/base-old/version"
echo bundle > "$set_dir/product-12.bin"
(cd "$set_dir" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS)
echo tampered > "$set_dir/product-12.bin"
if out="$(KEYS="$tmp/keys" OUT="$tmp/out" bash "$tmp/src/build/realci/cache.sh" restore "$set_dir" 2>&1)"; then
  bad "a restore took a set whose product-12.bin doesn't match its sum"
else
  grep -q 'product-12.bin' <<<"$out" || bad "a refused restore doesn't name the file: $out"
fi
[ ! -e "$tmp/out/product-12.bin" ] || bad "a refused restore left product-12.bin in OUT"
rm -f "$set_dir/SHA256SUMS"
if KEYS="$tmp/keys" OUT="$tmp/out" bash "$tmp/src/build/realci/cache.sh" restore "$set_dir" >/dev/null 2>&1; then
  bad "a restore took a set with no SHA256SUMS"
fi

# The workflow takes the old bundles only on the exact key, verifies them
# before the build uses them and saves only what it built.
wf="$root/.github/workflows/real-bundle.yml"
old_step="$(sed -n '/^      - name: Restore the old bundles$/,/^      - name: /p' "$wf")"
[ -n "$old_step" ] || bad "real-bundle.yml has no 'Restore the old bundles' step"
grep -q 'actions/cache/restore@' <<<"$old_step" || bad "the old bundles aren't restored with actions/cache/restore"
grep -q 'restore-keys' <<<"$old_step" && bad "the old bundles restore on a partial key"
grep -q 'key: ${{ steps.pins.outputs.old_key }}' <<<"$old_step" || bad "the old bundles' key isn't cache.sh's"
grep -q 'bash build/realci/cache.sh restore' "$wf" || bad "real-bundle.yml doesn't verify a restored set (cache.sh restore)"
save_if="$(sed -n '/^      - name: Save the old bundles$/,/^      - name: /p' "$wf" | grep -E '^        if:' || true)"
[ "$save_if" = "        if: steps.old.outputs.cache-hit != 'true'" ] || bad "the old bundles' save runs on '$save_if', not only on a miss"

[ "$fail" = 0 ] && echo "ok: the old bundles' cache key follows their pins and inputs, a restore checks its sums, and the workflow restores only on the exact key"
exit "$fail"
