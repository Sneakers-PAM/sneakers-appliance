#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# units.sh: make a build's three update units (spec 7) from the output of
# build/lab/build.sh, sealed with the same throwaway lab keys, or, with
# CHANNEL=production, from the release workflow's signed build, sealed in
# its sign job with the production release key (docs/release.md). A name
# carries the version on production and lab-<build label> on lab (the
# build's letter and rebuild number, lab-n3, or the product's own label,
# lab-sneakers.10); the build date, build time and commit stay in the
# signed header and the index:
#
#   sneakers-appliance-baseOS-<v>-amd64.bin               the Base OS full release
#   sneakers-appliance-<version>-amd64-LAB.bin            its bridge copy (BRIDGE=1)
#   sneakers-appliance-baseOS-patch-<b>-to-<v>-amd64.bin  a Base OS patch from each PATCH_FROM build
#                                                         (lab: ...-patch-lab-n2-to-n3-amd64.bin)
#   sneakers-appliance-baseWeb-<v>-amd64.bin              the Base Web, always: every Base OS ships with one
#   sneakers-product-<v>-amd64.bin                        the product bundle, as the build made it
#   sneakers-product-index.json                           the format 2 index over all of them
#
# On lab each unit is also there under the name the builds before the
# version-only names used (OLD_NAMES), listed in the index too, so a box
# running one of those builds still finds its update. Every new name is
# checked by build/release/check-names.sh.
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
#   PRODUCT_YAML, IMPORT_JOB, BRAND
#              the rest of what the product bundle is built from, for
#              `inputs product`, as build/product/build.sh takes them
#              (PRODUCT_YAML defaults to the lab's build/lab/product.yaml;
#              set it empty for none). The sealed product's .inputs is read
#              from its header (sneakers-artifact bin-inputs)
#   UNITS      the output directory (default $OUT/units)
#   BRIDGE     1 also writes the Base OS file under its old name and lists it
#              in the index's legacy base section, for boxes before the units
#   OLD_NAMES  1 (the lab default) also links each unit under the name the
#              builds before the version-only names gave it and lists it in
#              the index, and has each patch name its full release by that
#              name, for boxes running those builds; 0 leaves them out.
#              Lab only
#   PATCH_FROM build/lab/build.sh outputs to make a published patch from
#              (space-separated); a base may also be an earlier release's
#              Base OS unpacked (version and artifact/ only, as the release
#              job makes from the previous release): it's then opened with
#              UPDATE_KEY instead of its UKI, and checked by this build's
#              kit alone
#   UPDATE_KEY the update key, for a base without its UKI
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

# inputs_product: every file build/product/build.sh makes the bundle
# from: the release's pins (k0s, helm and every image digest, the migrate
# image among them), the stacks it applies, product.yaml, the import Job's
# template and the brand. The image countersignatures aren't inputs: they
# sign the digests release.yaml already pins. A file named but missing is
# refused, so it's never silently left out.
inputs_product() { # release.yaml stacks product.yaml import-job brand
  local f
  for f in "$1" "$3" "$4"; do
    [ -z "$f" ] || [ -f "$f" ] || { echo "units: $f, a product input, isn't there" >&2; return 1; }
  done
  [ -z "$5" ] || [ -d "$5" ] || { echo "units: the brand $5 isn't a directory" >&2; return 1; }
  {
    printf 'release %s\n' "$(sha256sum < "$1" | cut -d' ' -f1)"
    files "$2" | sed 's|^|stacks/|'
    if [ -n "$3" ]; then printf 'product.yaml %s\n' "$(sha256sum < "$3" | cut -d' ' -f1)"; fi
    if [ -n "$4" ]; then printf 'import-job %s\n' "$(sha256sum < "$4" | cut -d' ' -f1)"; fi
    if [ -n "$5" ]; then files "$5" | sed 's|^|brand/|'; fi
  } | digest
}

if [ "${1:-}" = inputs ]; then
  case "${2:-}" in
    baseOS) inputs_baseos ;;
    baseWeb) : "${PAGES:?PAGES is the built pages}"; inputs_baseweb "$PAGES" ;;
    product)
      : "${RELEASE:?RELEASE is the release.yaml}"
      inputs_product "$RELEASE" "${STACKS:-$here/stacks}" "${PRODUCT_YAML-$here/product.yaml}" "${IMPORT_JOB:-}" "${BRAND:-}" ;;
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
    [ "${OLD_NAMES:-0}" = 0 ] || { echo "units: OLD_NAMES is for lab builds only" >&2; exit 1; }
    ;;
  *) echo "units: CHANNEL is $channel, not lab or production" >&2; exit 1 ;;
esac
if [ -n "${BASEOS_INPUTS:-}" ] && ! [[ "$BASEOS_INPUTS" =~ ^[0-9a-f]{64}$ ]]; then
  echo "units: BASEOS_INPUTS isn't a SHA-256" >&2; exit 1
fi
pages="$OUT/work/osadmin"
[ -f "$pages/index.html" ] || { echo "units: a Base OS always ships with its Base Web, and $pages has no :8443 pages (build with WEB set)" >&2; exit 1; }
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
# The Base Web first: every Base OS release, full or patch, names the Base
# Web it ships with (spec 7, Section 4.4), built from the same pages its
# root carries, with a new version stamp even when the pages didn't change.
webin="$(inputs_baseweb "$pages")"
payload="$work/web-payload"
rm -rf "$payload"
manifest="$("$tool" web-pack --pages "$pages" --version "$version" --commit "$commit" --out "$payload" ${WEB_REQUIRES_MIN:+--requires-baseos-min "$WEB_REQUIRES_MIN"} ${WEB_REQUIRES_BEFORE:+--requires-baseos-before "$WEB_REQUIRES_BEFORE"})"
sign_blob "$manifest" "$payload/web.yaml.sig"
"$tool" web-check --dir "$payload" --release-key "$KEYS/cosign.pub"
webbin="$(seal baseweb "$payload" "$units" "$webin" --unit baseWeb --version "$version" ${WEB_REQUIRES_MIN:+--requires-baseos-min "$WEB_REQUIRES_MIN"} ${WEB_REQUIRES_BEFORE:+--requires-baseos-before "$WEB_REQUIRES_BEFORE"})"
echo "units: Base Web $(basename "$webbin") ($(stat -c %s "$webbin") bytes, inputs $webin)"
osin="${BASEOS_INPUTS:-$(inputs_baseos)}"
osbin="$(seal baseos "$OUT/artifact" "$units" "$osin" --unit baseOS --version "$version" --includes-baseweb "$version")"
echo "units: Base OS $(basename "$osbin") ($(stat -c %s "$osbin") bytes, inputs $osin)"
"$tool" bin-verify --release-key "$KEYS/cosign.pub" --channel "$channel" --identity-uki "$OUT/work/sneakers-$version.efi" "$osbin"
if [ "${BRIDGE:-}" = 1 ]; then
  legacy="$units/sneakers-appliance-$version-amd64-LAB.bin"
  cmp "$osbin" "$legacy" || { echo "units: the bridge copy isn't the same file" >&2; exit 1; }
  cp "$osbin.inputs" "$legacy.inputs"
  echo "units: bridge $(basename "$legacy")"
fi

# patch makes a patch from base (a build output) into dir and checks it.
patch() { # base dir
  local base="$1" dir="$2" bv
  bv="$(cat "$base/version")"
  local w="$work/patch-$bv"
  rm -rf "$w"
  "$tool" patch-make --base "$base/artifact" --target "$OUT/artifact" --out "$w" --zstd "${ZSTD:-zstd}"
  local pbin prev=()
  # A box from before the version-only names checks the patch's full .bin
  # against the names it knows, so with OLD_NAMES the patch names its full
  # release by the earlier name, which the mirror also has.
  if [ "$channel" = lab ] && [ "${OLD_NAMES:-1}" = 1 ]; then prev=(--previous-full-name); fi
  pbin="$(seal "patch-$bv" "$w/payload" "$dir" "$osin" --unit baseOS --version "$version" --includes-baseweb "$version" --patch-spec "$w/patch-spec.json" "${prev[@]}")"
  # Open it as a box on the base does, with the base's own UKI, rebuild the
  # target from the base, and verify the result with the base's kit.
  rm -rf "$w/rebuilt"
  local opener=(--identity-uki "$base/work/sneakers-$bv.efi")
  if [ ! -f "$base/work/sneakers-$bv.efi" ]; then
    : "${UPDATE_KEY:?the base $bv has no UKI; UPDATE_KEY opens its patch}"
    opener=(--identity "$UPDATE_KEY")
  fi
  "$tool" patch-check --base "$base/artifact" --release-key "$KEYS/cosign.pub" --channel "$channel" "${opener[@]}" --extract "$w/rebuilt" "$pbin"
  if [ -x "$base/sneakers-kit" ]; then "$base/sneakers-kit" verify "$w/rebuilt"; fi
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
  # The digest the bundle was built with, from its header: one worked out
  # again here could miss an input the build had (its brand, say).
  "$tool" bin-inputs "$p" > "$units/$(basename "$p").inputs"
done

# Each unit under its new name is checked; on lab it's also linked under
# the name the builds before the version-only names gave it.
named=()
for f in "$units"/*.bin; do
  [ -f "$f" ] || continue
  n="$(basename "$f")"
  [ "$n" = "$("$tool" bin-name "$f")" ] || continue
  named+=("$f")
  if [ "$channel" = lab ] && [ "${OLD_NAMES:-1}" = 1 ]; then
    old="$("$tool" bin-name --previous "$f")"
    if [ "$old" != "$n" ] && [ ! -e "$units/$old" ]; then
      ln "$f" "$units/$old" 2>/dev/null || cp "$f" "$units/$old"
      cp "$f.inputs" "$units/$old.inputs"
      echo "units: also as $old, for boxes before the version-only names"
    fi
  fi
done
bash "$root/build/release/check-names.sh" --channel "$channel" "${named[@]}" "${named[@]/%/.inputs}"

# The index lists every unit file here and in INDEX_ALSO, by the name it
# has; a file under the old name (a bridge copy) goes in the legacy base
# section.
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
