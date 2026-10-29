#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh: LAB ONLY, the real-bundle job's builds (docs/testing.md#the-real-bundle-job).
# Every piece is built the way the published lab builds were, from the
# commits build/realci/pins.env names, and signed with one lab key set
# made for the run:
#
#   OUT/base-old/      the base the boxes run today (n6): build/lab/build.sh
#                      at OLD_BASE_COMMIT, its raw disk to install
#   OUT/base-new/      the base under test (n7): build/lab/build.sh at
#                      UNDER_TEST, and OUT/base-new.bin, its Base OS update
#                      (sneakers-artifact bin-pack, as the release
#                      workflow's lab job packs one)
#   OUT/product-12.bin the real Sneakers product without phases (.12)
#   OUT/product-13.bin the first one with phases (.13)
#   OUT/product-next.bin the product under test (UNDER_TEST, version
#                      0.1.0-lab.realci.next, newer than .13)
#   OUT/bin/sneakers-migrate, OUT/bin/synth
#                      the next release's, for the import leg's source
#                      (build/realci/source.sh)
#   OUT/realci.env     the paths and versions, for the image test
#
# Each product is the production path with lab keys: the service images
# from build/release/images.sh (each from the commit its sneakers-release
# pins), bundle fill, every pinned manifest signed with the lab key, the
# production render (build/product/sneakers/render.sh), product.yaml, the
# import Job, build/product/build.sh, then sealed. Each product and each
# base is built by its own commit's scripts; only the lab hook
# (build/lab/overlay) is this commit's, so the test reads the same lines
# from every base.
#
# Inputs (environment):
#   KEYS        a directory for the lab keys (CI: a fresh tmpfs); a key
#               set already there is reused
#   OUT         the output directory
#   UNDER_TEST  the commit under test (default HEAD); CONTROL=1 takes
#               CONTROL_COMMIT from pins.env instead
#   NEXT_RELEASE the sneakers-release commit "next" is built with (default
#               NEXT_RELEASE_COMMIT, empty: its main now); the workflow
#               resolves it once, to key next's service images on it
#   LAYOUTS     a directory of service image layouts per sneakers-release
#               commit (OUT/layouts by default); a commit already there
#               isn't built again
#   KERNEL, KERNELRELEASE, VERITYSETUP, OPENSSH, BUSYBOX, STATIC
#               the components, as build/lab/build.sh takes them; a tree
#               whose stamps differ builds its own static tools
#   STATIC_CACHE  where those are kept per commit (OUT/static-cache by
#               default)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${KEYS:?}" "${OUT:?}" "${KERNEL:?}" "${KERNELRELEASE:?}" "${VERITYSETUP:?}" "${OPENSSH:?}" "${BUSYBOX:?}" "${STATIC:?}"
# shellcheck source=build/realci/pins.env
source "$here/pins.env"
say() { echo "realci: $*"; }
abs() { (cd "$(dirname "$1")" && echo "$PWD/$(basename "$1")"); }
for v in KERNEL VERITYSETUP OPENSSH BUSYBOX STATIC; do
  printf -v "$v" '%s' "$(abs "${!v}")"
done
mkdir -p "$OUT" "$KEYS"
OUT="$(abs "$OUT")" KEYS="$(abs "$KEYS")"
layouts="$(abs "${LAYOUTS:-$OUT/layouts}")"
# build/product/build.sh reads LAYOUTS too: each product gets its own.
unset LAYOUTS
mkdir -p "$layouts"
export COSIGN_PASSWORD=""
under="${UNDER_TEST:-$(git -C "$root" rev-parse HEAD)}"
if [ "${CONTROL:-}" = 1 ]; then under="$CONTROL_COMMIT"; fi
under="$(git -C "$root" rev-parse "$under^{commit}")"
next_release="${NEXT_RELEASE:-$NEXT_RELEASE_COMMIT}"
if [ -z "$next_release" ]; then
  next_release="$(git ls-remote https://github.com/Sneakers-PAM/sneakers-release.git refs/heads/main | cut -f1)"
fi
say "old base $OLD_BASE_COMMIT, under test $under; .12 $P12_APPLIANCE_COMMIT+$P12_RELEASE_COMMIT, .13 $P13_APPLIANCE_COMMIT+$P13_RELEASE_COMMIT, next $under+$next_release"

# tree <commit>: a checkout of this repository at the commit, with this
# commit's lab hook.
tree() {
  local dir="$OUT/src/$1"
  if [ ! -d "$dir" ]; then
    git clone -q --shared --no-checkout "$root" "$dir"
    git -C "$dir" checkout -q --detach "$1"
    cp -a "$root/build/lab/overlay/." "$dir/build/lab/overlay/"
  fi
  echo "$dir"
}
# release <commit>: a sneakers-release checkout at the commit.
release() {
  local dir="$OUT/release/$1"
  if [ ! -d "$dir/.git" ]; then
    git init -q "$dir"
    git -C "$dir" fetch -q --depth 1 https://github.com/Sneakers-PAM/sneakers-release.git "$1"
    git -C "$dir" checkout -q FETCH_HEAD
  fi
  [ "$(git -C "$dir" rev-parse HEAD)" = "$1" ] || { echo "realci: sneakers-release fetched $(git -C "$dir" rev-parse HEAD) for $1" >&2; exit 1; }
  echo "$dir"
}
reuse=()
keyset() { if [ -e "$KEYS/cosign.key" ]; then reuse=(REUSE_KEYS=1); else reuse=(); fi; }

# components <tree>: the static tools that tree's root build takes. Each
# one is stamped with the pins and build script of the tree that built it
# (build/lib/stamp.sh), so a tree whose stamps differ from the given
# components' builds its own with its own scripts, kept in
# STATIC_CACHE/<commit> (CI caches it). Sets c_static, c_openssh and
# c_busybox.
components() {
  local src="$1" commit stale cache
  commit="$(git -C "$src" rev-parse HEAD)"
  cache="${STATIC_CACHE:-$OUT/static-cache}/$commit"
  # stale <static dir> <openssh dir> <busybox>: the tools whose stamp isn't
  # this tree's.
  stale() {
    (
      # shellcheck source=build/lib/stamp.sh
      source "$src/build/lib/stamp.sh"
      # A tree from before the guest agent (qemu-ga) has no script for it.
      for t in cryptsetup e2fsprogs gptfdisk procps qemu-ga; do
        [ -f "$src/build/static/$t.sh" ] || continue
        stamp_check "$1/$t-amd64.stamp" "$(static_stamp "$t" amd64)" "$t" >/dev/null 2>&1 || echo "$t"
      done
      stamp_check "$2/openssh.stamp" "$(openssh_stamp)" openssh >/dev/null 2>&1 || echo openssh
      stamp_check "$(dirname "$3")/busybox.stamp" "$(busybox_stamp)" busybox >/dev/null 2>&1 || echo busybox
    )
  }
  c_static="$STATIC" c_openssh="$OPENSSH" c_busybox="$BUSYBOX"
  stale="$(stale "$STATIC" "$OPENSSH" "$BUSYBOX")"
  [ -n "$stale" ] || return 0
  if [ -d "$cache" ] && [ -z "$(stale "$cache/static" "$cache/ssh" "$cache/ssh/busybox")" ]; then
    say "components for ${commit:0:7}: from the cache"
  else
    say "components for ${commit:0:7}: building $(echo "$stale" | tr '\n' ' ')with its own scripts"
    mkdir -p "$cache/static" "$cache/ssh" "$src/build/out"
    cp -a "$STATIC"/*-amd64* "$src/build/out/"
    cp -a "$OPENSSH/." "$cache/ssh/"
    cp -a "$BUSYBOX" "$(dirname "$BUSYBOX")/busybox.stamp" "$cache/ssh/" 2>/dev/null || true
    for t in $stale; do
      case "$t" in
        openssh) (cd "$src" && bash build/openssh/build.sh "$cache/ssh") > "$OUT/components-$t.log" 2>&1 || { tail -30 "$OUT/components-$t.log" >&2; exit 1; } ;;
        busybox) (cd "$src" && bash build/busybox/build.sh "$cache/ssh") > "$OUT/components-$t.log" 2>&1 || { tail -30 "$OUT/components-$t.log" >&2; exit 1; } ;;
        *) (cd "$src" && bash "build/static/$t.sh" amd64) > "$OUT/components-$t.log" 2>&1 || { tail -30 "$OUT/components-$t.log" >&2; exit 1; } ;;
      esac
    done
    cp -a "$src/build/out/." "$cache/static/"
    [ -z "$(stale "$cache/static" "$cache/ssh" "$cache/ssh/busybox")" ] || { echo "realci: ${commit:0:7}'s components are still stale" >&2; exit 1; }
  fi
  c_static="$cache/static" c_openssh="$cache/ssh" c_busybox="$cache/ssh/busybox"
}

# base <name> <commit> <version>
base() {
  local src start
  src="$(tree "$2")"
  if [ -s "$OUT/$1/version" ] && [ -n "$(ls "$OUT/$1/disk" 2>/dev/null)" ]; then say "base $1: $(cat "$OUT/$1/version"), built already"; return; fi
  start="$(date +%s)"
  keyset
  components "$src"
  say "base $1 from $2"
  (cd "$src" && env "${reuse[@]}" KERNEL="$KERNEL" KERNELRELEASE="$KERNELRELEASE" VERITYSETUP="$c_static/veritysetup-amd64" \
    OPENSSH="$c_openssh" BUSYBOX="$c_busybox" STATIC="$c_static" KEYS="$KEYS" VERSION="$3" OUT="$OUT/$1" \
    bash build/lab/build.sh) > "$OUT/$1.log" 2>&1 || { tail -40 "$OUT/$1.log" >&2; exit 1; }
  say "base $1: $(cat "$OUT/$1/version") in $(( $(date +%s) - start ))s"
}
base base-old "$OLD_BASE_COMMIT" 0.0.6
base base-new "$under" 0.0.7
old_version="$(cat "$OUT/base-old/version")" new_version="$(cat "$OUT/base-new/version")"
# The k0s and helm the lab build fetched and checked (build/ci/versions.env).
bin_dir="$OUT/bin"
mkdir -p "$bin_dir"
install -m 0755 "$OUT/base-new/work/k0s" "$OUT/bin/k0s"
install -m 0755 "$OUT/base-new/work/helm" "$OUT/bin/helm"

# The base under test as the Base OS update a box on the old base applies.
src="$(tree "$under")"
tool="$OUT/sneakers-artifact"
(cd "$src" && CGO_ENABLED=0 go build -trimpath -o "$tool" ./cmd/sneakers-artifact)
"$tool" bin-pack --layout "$OUT/base-new/artifact" --recipient "$KEYS/update.pub" --unit baseOS --commit "${under:0:7}" \
  --version "$new_version" --arch amd64 --channel lab --out "$OUT/base-new-bin" >/dev/null
cosign sign-blob --yes --key "$KEYS/cosign.key" --bundle "$OUT/base-new-bin/header.sigstore.json" \
  --tlog-upload=false --use-signing-config=false "$OUT/base-new-bin/header.json" >/dev/null 2>&1
bin="$("$tool" bin-seal --work "$OUT/base-new-bin" --bundle "$OUT/base-new-bin/header.sigstore.json" --out "$OUT/base-new-units")"
cp "$bin" "$OUT/base-new.bin"
"$tool" bin-verify --release-key "$KEYS/cosign.pub" --channel lab --identity-uki "$OUT/base-old/work/sneakers-$old_version.efi" "$OUT/base-new.bin" >/dev/null
say "base-new.bin $(stat -c %s "$OUT/base-new.bin") bytes, opens with the old base's UKI"

# product <label> <appliance commit> <release commit>
product() {
  local label="$1" src rel lay b version start bin
  src="$(tree "$2")" rel="$(release "$3")" lay="$layouts/$3" b="$OUT/product-$label"
  version="0.1.0-lab.realci.$label"
  if [ -s "$OUT/product-$label.bin" ]; then say "product .$label: built already"; return; fi
  start="$(date +%s)"
  if [ ! -e "$lay/.done" ]; then
    say "service images for sneakers-release $3"
    mkdir -p "$(dirname "$lay")"
    (cd "$src" && RELEASE="$rel/manifest/release.yaml" OUT="$lay" bash build/release/images.sh) > "$OUT/images-$3.log" 2>&1 \
      || { tail -40 "$OUT/images-$3.log" >&2; exit 1; }
    : > "$lay/.done"
  fi
  mkdir -p "$b"
  sed "0,/^  version: .*$/s//  version: $version/" "$rel/manifest/release.yaml" > "$b/release-src.yaml"
  grep -q "^  version: $version$" "$b/release-src.yaml"
  (cd "$src" && VERSION="$version" OUT="$b" CHARTS="$rel" LAYOUTS="$lay" KEYS="$KEYS" MIN_BASE="$old_version" \
    K0S="$bin_dir/k0s" HELM="$bin_dir/helm" bash "$here/product.sh") > "$OUT/product-$label.log" 2>&1 \
    || { tail -40 "$OUT/product-$label.log" >&2; exit 1; }
  cosign sign-blob --yes --key "$KEYS/cosign.key" --bundle "$b/work/bin/header.sigstore.json" \
    --tlog-upload=false --use-signing-config=false "$b/work/bin/header.json" >/dev/null 2>&1
  bin="$("$tool" bin-seal --work "$b/work/bin" --bundle "$b/work/bin/header.sigstore.json" --out "$b/out")"
  cp "$bin" "$OUT/product-$label.bin"
  "$tool" bin-verify --release-key "$KEYS/cosign.pub" --channel lab --identity-uki "$OUT/base-old/work/sneakers-$old_version.efi" "$OUT/product-$label.bin" >/dev/null
  say "product .$label: $version, $(stat -c %s "$OUT/product-$label.bin") bytes, $(wc -l < "$b/images.txt") images, phases: $(grep -c '^  - name:' <(sed -n '/^phases:/,/^[a-z]/p' "$src/build/product/sneakers/product.yaml")), in $(( $(date +%s) - start ))s"
  # The tree under the work directory is the unpacked bundle: drop it.
  rm -rf "$b/work/tree"
}
product 12 "$P12_APPLIANCE_COMMIT" "$P12_RELEASE_COMMIT"
product 13 "$P13_APPLIANCE_COMMIT" "$P13_RELEASE_COMMIT"
product next "$under" "$next_release"

# The import leg's source (build/realci/source.sh): the next release's
# sneakers-migrate and synth, built for the runner.
rel_next="$(release "$next_release")"
(cd "$rel_next" && CGO_ENABLED=0 go build -trimpath -o "$bin_dir/sneakers-migrate" ./migrate/cmd/sneakers-migrate &&
  CGO_ENABLED=0 go build -trimpath -o "$bin_dir/synth" ./migrate/test/synth)
say "the import source's tools from sneakers-release $next_release"

cat > "$OUT/realci.env" <<ENV
SNEAKERS_KEYS=$KEYS
SNEAKERS_REAL_OLD_IMAGE=$(ls "$OUT"/base-old/disk/*.raw)
SNEAKERS_REAL_OLD_VERSION=$old_version
SNEAKERS_REAL_NEW_BASE=$OUT/base-new.bin
SNEAKERS_REAL_NEW_VERSION=$new_version
SNEAKERS_REAL_NEW_IMAGE=$(ls "$OUT"/base-new/disk/*.raw)
SNEAKERS_REAL_P12=$OUT/product-12.bin
SNEAKERS_REAL_P13=$OUT/product-13.bin
SNEAKERS_REAL_NEXT=$OUT/product-next.bin
SNEAKERS_REAL_RELEASE_SRC=$rel_next
SNEAKERS_REAL_MIGRATE=$bin_dir/sneakers-migrate
SNEAKERS_REAL_SYNTH=$bin_dir/synth
ENV
say "done: $(tr '\n' ' ' < "$OUT/realci.env")"
