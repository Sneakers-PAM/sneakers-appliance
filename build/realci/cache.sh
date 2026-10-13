#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# cache.sh: LAB ONLY, the real-bundle job's cache of the old bundles (the
# old base and the .12 and .13 products, build/realci/build.sh), which
# only their pins and inputs decide (docs/testing.md#the-cache). The set is
# one cache entry with the lab key set that signed it, so the base under
# test and the product under test are signed with that set too.
#
#   cache.sh key            the cache key: realci-old-<SHA-256 of the pins
#                           and of every input that shapes the old bundles>
#   cache.sh next           the sneakers-release commit "next" is built
#                           with (NEXT_RELEASE_COMMIT, or its main now)
#   cache.sh save <dir>     put OUT's old bundles in <dir> (hard links)
#                           with their SHA256SUMS
#   cache.sh restore <dir>  check a restored <dir> as a fresh build is
#                           checked (its sums, the key set it was signed
#                           with, the UKI's signature, the kit's verify of
#                           the base, then the base's raw disk from it) and
#                           move it into OUT; build.sh then bin-verifies
#                           each product as it does one it built
#
# Inputs (environment): OUT and KEYS for save and restore (build.sh's);
# ROOT the tree the key is of (default this checkout);
# REALCI_TOOL_VERSIONS the runner's build tool versions (default: from
# dpkg); DISK_SIZE the raw disk's size (build/lab/build.sh's default).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="${ROOT:-$(cd "$here/../.." && pwd)}"
say() { echo "realci: $*"; }
die() { echo "realci: $*" >&2; exit 1; }

# The runner's tools the old base's build signs, packs and assembles with.
tool_versions() {
  dpkg-query -W -f='${Package} ${Version} ' sbsigntool systemd-boot-efi systemd-ukify python3-pefile \
    squashfs-tools cryptsetup-bin efitools cpio mtools 2>/dev/null || echo none
}

# The files that shape the old bundles in this tree (ROOT, a git checkout): the realci and image
# scripts; the lab hook every base carries; the kernel and static tools
# the old base is built with when its stamps match; versions.env (k0s,
# helm and cosign); and the Go source sneakers-artifact seals the
# products with.
inputs() {
  (
    cd "$root"
    printf '%s\n' build/realci/build.sh build/realci/product.sh build/realci/cache.sh build/release/images.sh \
      build/ci/versions.env build/ci/install-cosign.sh go.mod go.sum
    # Tracked files only: a kernel or static tool build leaves its work in
    # some of these folders, which mustn't move the key.
    git ls-files -- build/lab/overlay os/kernel build/kernel build/static build/lib build/openssh build/busybox
    go list -deps -f '{{if and .Module .Module.Main}}{{range .GoFiles}}{{$.Dir}}/{{.}}
{{end}}{{range .EmbedFiles}}{{$.Dir}}/{{.}}
{{end}}{{end}}' ./cmd/sneakers-artifact | sed "s|^$PWD/||"
  ) | sed '/^$/d' | LC_ALL=C sort -u
}

key() {
  # shellcheck source=build/realci/pins.env
  source "$root/build/realci/pins.env"
  local list
  list="$(inputs)"
  {
    for v in OLD_BASE_COMMIT P12_APPLIANCE_COMMIT P12_RELEASE_COMMIT P13_APPLIANCE_COMMIT P13_RELEASE_COMMIT; do
      echo "$v=${!v}"
    done
    echo "tools ${REALCI_TOOL_VERSIONS:-$(tool_versions)}"
    (cd "$root" && tr '\n' '\0' <<<"$list" | xargs -0 sha256sum)
  } | sha256sum | sed 's/^\([0-9a-f]*\).*/realci-old-\1/'
}

next() {
  # shellcheck source=build/realci/pins.env
  source "$root/build/realci/pins.env"
  local c="$NEXT_RELEASE_COMMIT"
  if [ -z "$c" ]; then
    c="$(git ls-remote https://github.com/Sneakers-PAM/sneakers-release.git refs/heads/main | cut -f1)"
  fi
  [[ "$c" =~ ^[0-9a-f]{40}$ ]] || die "sneakers-release's next commit is '$c'"
  echo "$c"
}

# The old bundles' files, relative to OUT.
files() {
  local v
  v="$(cat "$1/base-old/version")"
  printf '%s\n' base-old/version base-old/keys.txt base-old/sneakers-kit "base-old/work/sneakers-$v.efi" product-12.bin product-13.bin
  (cd "$1" && find base-old/artifact -type f)
}

save() {
  local dir="$1"
  : "${OUT:?}"
  [ ! -e "$dir" ] || die "$dir is there already"
  mkdir -p "$dir"
  files "$OUT" | while read -r f; do
    mkdir -p "$dir/$(dirname "$f")"
    cp -al "$OUT/$f" "$dir/$f"
  done
  (cd "$dir" && find . -type f ! -path ./SHA256SUMS | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
  say "old bundles saved for the cache: $(($(wc -l < "$dir/SHA256SUMS"))) files, $(du -sh "$dir" | cut -f1)"
}

restore() {
  local dir="$1" v efi f
  : "${OUT:?}" "${KEYS:?}"
  [ -s "$dir/SHA256SUMS" ] || die "the restored old bundles have no SHA256SUMS"
  (cd "$dir" && sha256sum -c --quiet SHA256SUMS) || die "the restored old bundles don't match their SHA256SUMS"
  f="$(cd "$dir" && comm -3 <(find . -type f ! -path ./SHA256SUMS | LC_ALL=C sort) <(sed 's/^[0-9a-f]*  //' SHA256SUMS | LC_ALL=C sort))"
  [ -z "$f" ] || die "the restored old bundles have files SHA256SUMS doesn't list: $f"
  v="$(cat "$dir/base-old/version")" efi="$dir/base-old/work/sneakers-$v.efi"
  # The key set restored with them is the one that signed them.
  bash "$root/build/release/check-fingerprints.sh" "$KEYS" "$dir/base-old/keys.txt" >/dev/null 2>&1 \
    || die "the restored key set isn't the one the old base recorded in keys.txt"
  [ -e "$KEYS/cosign.key" ] || die "the restored key set has no cosign.key"
  sbverify --cert "$KEYS/db.crt" "$efi" >/dev/null 2>&1 || die "the old base's UKI isn't signed by the restored db key"
  "$dir/base-old/sneakers-kit" verify "$dir/base-old/artifact" >/dev/null || die "the old base's artifact doesn't verify"
  mkdir -p "$OUT"
  [ ! -e "$OUT/base-old" ] || die "$OUT/base-old is there already"
  for f in base-old product-12.bin product-13.bin; do mv "$dir/$f" "$OUT/$f"; done
  mkdir -p "$OUT/base-old/disk"
  "$OUT/base-old/sneakers-kit" build "$OUT/base-old/artifact" --format raw --disk-size "${DISK_SIZE:-64G}" --out "$OUT/base-old/disk" >/dev/null
  say "old bundles from the cache: base $v, .12 and .13, sums, keys, UKI and artifact verified, raw disk $(ls "$OUT/base-old/disk")"
}

case "${1:-}" in
  key) key ;;
  next) next ;;
  save) save "${2:?usage: cache.sh save <dir>}" ;;
  restore) restore "${2:?usage: cache.sh restore <dir>}" ;;
  *) die "usage: cache.sh key|next|save <dir>|restore <dir>" ;;
esac
