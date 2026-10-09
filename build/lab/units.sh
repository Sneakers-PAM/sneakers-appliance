#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# units.sh: make a build's three update units (spec 7) from the output of
# build/lab/build.sh, sealed with the same throwaway lab keys, or, with
# CHANNEL=production, from the release workflow's signed build, sealed in
# its sign job with the production release key (docs/release.md). The
# names below are the lab ones; a production file has no -LAB, and its
# Base OS and Base Web versions carry -g<commit> once:
#
#   sneakers-appliance-baseOS-<version>-amd64-LAB.bin   the Base OS full release
#   sneakers-appliance-<version>-amd64-LAB.bin          its bridge copy (BRIDGE=1)
#   sneakers-appliance-baseOS-patch-<v>-from-<b>-...    a Base OS patch from each PATCH_FROM build
#   sneakers-appliance-baseWeb-<version>-amd64-LAB.bin  the Base Web (when the build made pages)
#   sneakers-product-<version>-amd64-LAB.bin            the product bundle, as the build made it
#   sneakers-product-index.json                         the format 2 index over all of them
#
# Every .bin has a <file>.inputs next to it: the SHA-256 of the unit's
# build inputs, also in its signed header, so a release job can compare it
# with the last published release's and build only the units that changed.
# Every patch is rebuilt with the box's own code and checked against the
# target before it's kept (sneakers-artifact patch-check), and the rebuilt
# layout is verified by the base build's kit, as a box on the base would.
#
# Usage:
#   units.sh                      make the units (environment below)
#   units.sh inputs <unit>        print a unit's input digest: baseOS, baseWeb or product
#
# Inputs (environment):
#   OUT        a build/lab/build.sh output (the target release), or the
#              same layout made by the release workflow: version, artifact/,
#              work/sneakers-<version>.efi (the signed UKI), work/osadmin/
#              (the pages), work/release.yaml and product/
#   KEYS       the key set that build used: cosign.key (its password in
#              COSIGN_PASSWORD), cosign.pub and update.pub
#   CHANNEL    lab (default) or production
#   COMMIT     the short commit the build is from; required for production
#              (a lab version ends with it)
#   BASEOS_INPUTS
#              the Base OS input digest, when the build job computed it
#              (the components aren't there when the units are sealed)
#   STACKS     the product's stacks, for its input digest (default the lab
#              stacks, build/lab/stacks)
#   UNITS      the output directory (default $OUT/units)
#   BRIDGE     1 also writes the Base OS file under its old name and lists it
#              in the index's legacy base section, for boxes before the units
#   PATCH_FROM build/lab/build.sh outputs to make a published patch from
#              (space-separated)
#   CHECK_FROM outputs to make a patch from that is built and checked but not
#              published: it goes to $UNITS/checked-only, out of the index
#   INDEX_ALSO directories whose .bin files the index lists too (an earlier
#              release's units on the same mirror)
#   KERNEL, VERITYSETUP, OPENSSH, BUSYBOX, STATIC
#              the components the build took, for the Base OS input digest
#   ZSTD       the zstd command (default zstd)
set -euo pipefail
shopt -s inherit_errexit

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

# digest prints the SHA-256 of a "name sha" list, sorted.
digest() { LC_ALL=C sort | sha256sum | cut -d' ' -f1; }

# files lists "path sha" for every regular file under a directory.
files() { # dir
  (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0r sha256sum | awk '{ print $2, $1 }')
}

# inputs_baseos: the appliance tree at the commit built, and each pinned
# component the build took.
inputs_baseos() {
  {
    printf 'tree %s\n' "$(git -C "$root" rev-parse HEAD^{tree})"
    for v in KERNEL VERITYSETUP BUSYBOX; do
      if [ -n "${!v:-}" ] && [ -f "${!v}" ]; then printf '%s %s\n' "$v" "$(sha256sum < "${!v}" | cut -d' ' -f1)"; fi
    done
    for v in OPENSSH STATIC; do
      if [ -n "${!v:-}" ] && [ -d "${!v}" ]; then files "${!v}" | sed "s|^|$v/|"; fi
    done
  } | digest
}

# inputs_baseweb: the built pages.
inputs_baseweb() { # pages
  files "$1" | digest
}

# inputs_product: the release's pins (k0s, helm and every image digest)
# and the stacks it applies.
inputs_product() { # release.yaml stacks
  { printf 'release %s\n' "$(sha256sum < "$1" | cut -d' ' -f1)"; files "$2" | sed 's|^|stacks/|'; } | digest
}

if [ "${1:-}" = inputs ]; then
  case "${2:-}" in
    baseOS) inputs_baseos ;;
    baseWeb) : "${PAGES:?PAGES is the built pages}"; inputs_baseweb "$PAGES" ;;
    product) : "${RELEASE:?RELEASE is the release.yaml}"; inputs_product "$RELEASE" "${STACKS:-$here/stacks}" ;;
    *) echo "units: inputs takes baseOS, baseWeb or product" >&2; exit 2 ;;
  esac
  exit 0
fi

: "${OUT:?}" "${KEYS:?}"
units="${UNITS:-$OUT/units}"
channel="${CHANNEL:-lab}"
version="$(cat "$OUT/version")"
case "$channel" in
  lab)
    commit="${version##*-g}"
    [[ "$commit" =~ ^[0-9a-f]{7}$ ]] || { echo "units: $version doesn't end with -g<commit>" >&2; exit 1; }
    ;;
  production)
    commit="${COMMIT:-}"
    [[ "$commit" =~ ^[0-9a-f]{7,40}$ ]] || { echo "units: a production build needs COMMIT, its commit in hex (got '$commit')" >&2; exit 1; }
    commit="${commit:0:7}"
    # The first production release is full units only; boxes before the
    # units never ran a production build, so there's nothing to bridge.
    [ "${BRIDGE:-}" != 1 ] || { echo "units: BRIDGE is for lab builds only" >&2; exit 1; }
    ;;
  *) echo "units: CHANNEL is $channel, not lab or production" >&2; exit 1 ;;
esac
if [ -n "${BASEOS_INPUTS:-}" ] && ! [[ "$BASEOS_INPUTS" =~ ^[0-9a-f]{64}$ ]]; then
  echo "units: BASEOS_INPUTS isn't a SHA-256" >&2; exit 1
fi
export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"
work="$OUT/work/units"
rm -rf "$work"
mkdir -p "$work" "$units"
go build -o "$work/sneakers-artifact" "$root/cmd/sneakers-artifact"
tool="$work/sneakers-artifact"

sign_blob() { # file bundle
  cosign sign-blob --yes --key "$KEYS/cosign.key" --bundle "$2" \
    --tlog-upload=false --use-signing-config=false "$1" >/dev/null 2>&1
}

# seal packs layout as a unit's .bin into dir, with its inputs beside it,
# and prints the file. Extra arguments go to bin-pack.
seal() { # name layout dir inputs [bin-pack args...]
  local name="$1" layout="$2" dir="$3" inputs="$4"
  shift 4
  local w="$work/seal-$name"
  rm -rf "$w"
  "$tool" bin-pack --layout "$layout" --recipient "$KEYS/update.pub" --arch amd64 --channel "$channel" \
    --commit "$commit" --inputs "$inputs" --out "$w" "$@" >/dev/null
  sign_blob "$w/header.json" "$w/header.sigstore.json"
  local seal_args=()
  if [ "$name" = baseos ] && [ "${BRIDGE:-}" = 1 ]; then seal_args+=(--bridge); fi
  mkdir -p "$dir"
  local bin
  bin="$("$tool" bin-seal --work "$w" --bundle "$w/header.sigstore.json" --out "$dir" "${seal_args[@]}")"
  printf '%s\n' "$inputs" > "$bin.inputs"
  printf '%s\n' "$bin"
}

echo "units: $version"
osin="${BASEOS_INPUTS:-$(inputs_baseos)}"
osbin="$(seal baseos "$OUT/artifact" "$units" "$osin" --unit baseOS --version "$version")"
echo "units: Base OS $(basename "$osbin") ($(stat -c %s "$osbin") bytes, inputs $osin)"
"$tool" bin-verify --release-key "$KEYS/cosign.pub" --channel "$channel" --identity-uki "$OUT/work/sneakers-$version.efi" "$osbin"
if [ "${BRIDGE:-}" = 1 ]; then
  legacy="$units/sneakers-appliance-$version-amd64-LAB.bin"
  cmp "$osbin" "$legacy" || { echo "units: the bridge copy isn't the same file" >&2; exit 1; }
  cp "$osbin.inputs" "$legacy.inputs"
  echo "units: bridge $(basename "$legacy")"
fi

pages="$OUT/work/osadmin"
if [ -f "$pages/index.html" ]; then
  webin="$(inputs_baseweb "$pages")"
  payload="$work/web-payload"
  rm -rf "$payload"
  manifest="$("$tool" web-pack --pages "$pages" --version "$version" --commit "$commit" --out "$payload" ${WEB_REQUIRES_MIN:+--requires-baseos-min "$WEB_REQUIRES_MIN"} ${WEB_REQUIRES_BEFORE:+--requires-baseos-before "$WEB_REQUIRES_BEFORE"})"
  sign_blob "$manifest" "$payload/web.yaml.sig"
  "$tool" web-check --dir "$payload" --release-key "$KEYS/cosign.pub"
  webbin="$(seal baseweb "$payload" "$units" "$webin" --unit baseWeb --version "$version" ${WEB_REQUIRES_MIN:+--requires-baseos-min "$WEB_REQUIRES_MIN"} ${WEB_REQUIRES_BEFORE:+--requires-baseos-before "$WEB_REQUIRES_BEFORE"})"
  echo "units: Base Web $(basename "$webbin") ($(stat -c %s "$webbin") bytes, inputs $webin)"
else
  echo "units: the build made no :8443 pages (WEB unset); no Base Web"
fi

# patch makes a patch from base (a build output) into dir and checks it.
patch() { # base dir
  local base="$1" dir="$2" bv
  bv="$(cat "$base/version")"
  local w="$work/patch-$bv"
  rm -rf "$w"
  "$tool" patch-make --base "$base/artifact" --target "$OUT/artifact" --out "$w" --zstd "${ZSTD:-zstd}"
  local pbin
  pbin="$(seal "patch-$bv" "$w/payload" "$dir" "$osin" --unit baseOS --version "$version" --patch-spec "$w/patch-spec.json")"
  # Open it as a box on the base does, with the base's own UKI, rebuild the
  # target from the base, and verify the result with the base's kit.
  rm -rf "$w/rebuilt"
  "$tool" patch-check --base "$base/artifact" --release-key "$KEYS/cosign.pub" --channel "$channel" --identity-uki "$base/work/sneakers-$bv.efi" --extract "$w/rebuilt" "$pbin"
  "$base/sneakers-kit" verify "$w/rebuilt"
  "$OUT/sneakers-kit" verify "$w/rebuilt"
  local ps fs
  ps="$(stat -c %s "$pbin")" fs="$(stat -c %s "$osbin")"
  echo "units: patch $(basename "$pbin"): $ps bytes, the full file $fs bytes"
}
for b in ${PATCH_FROM:-}; do patch "$b" "$units"; done
for b in ${CHECK_FROM:-}; do patch "$b" "$units/checked-only"; done

for p in "$OUT"/product/sneakers-product-*.bin; do
  [ -f "$p" ] || continue
  cp "$p" "$units/"
  printf '%s\n' "$(inputs_product "$OUT/work/release.yaml" "${STACKS:-$here/stacks}")" > "$units/$(basename "$p").inputs"
done

# The index lists every unit file here and in INDEX_ALSO; a file under the
# old name (a bridge copy) goes in the legacy base section.
bins=() bridges=()
for d in "$units" ${INDEX_ALSO:-}; do
  for f in "$d"/*.bin; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in
      sneakers-appliance-[0-9]*) bridges+=(--bridge "$f") ;;
      *) bins+=("$f") ;;
    esac
  done
done
"$tool" index --out "$units/sneakers-product-index.json" "${bridges[@]}" "${bins[@]}" >/dev/null
( cd "$units" && sha256sum -- *.bin > SHA256SUMS )
echo "units: index of ${#bins[@]} files and $(( ${#bridges[@]} / 2 )) bridge copies: $units/sneakers-product-index.json"
