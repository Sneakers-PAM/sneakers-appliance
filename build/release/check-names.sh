#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# check-names.sh: refuse a built or published file whose name isn't one of
# the release's allowed shapes (docs/release.md, "File names"). A name
# carries the version on production and lab-<build label> on lab; never a
# build date (8 digits), a build-time stamp (r<14 digits) or a commit
# (-g<hex>), which the signed header and the index carry instead.
#
# Usage: check-names.sh --channel production|lab <file>...
# Only the base name of each file is read.
set -euo pipefail
[ "${1:-}" = --channel ] || { echo "check-names: usage: check-names.sh --channel production|lab <file>..." >&2; exit 2; }
channel="${2:-}"
shift 2 || true
case "$channel" in
  production) v='[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?' ;;
  lab) v='lab-[0-9a-z]+([.-][0-9a-z]+)*' ;;
  *) echo "check-names: the channel is '$channel', not production or lab" >&2; exit 2 ;;
esac
[ "$#" -gt 0 ] || { echo "check-names: name the files" >&2; exit 2; }
label="${v#lab-}"
patch_v="$v-to-$v"
[ "$channel" = lab ] && patch_v="$v-to-$label"
arch='(amd64|arm64)'
sidecar='(\.inputs|\.sha256|\.sigstore\.json|\.sig)?'
images="sneakers-appliance-$v-amd64\.(ova|qcow2|iso)|sneakers-appliance-$v-arm64\.img\.xz"
[ "$channel" = lab ] && images="$images|sneakers-appliance-$v-$arch\.raw"
allowed="^((sneakers-appliance-baseOS-$v|sneakers-appliance-baseWeb-$v|sneakers-appliance-baseOS-patch-$patch_v|sneakers-product-$v)-$arch\.bin|$images)$sidecar\$"
fixed='^(sneakers-product-index\.json|SHA256SUMS|release\.yaml)(\.sigstore\.json)?$'
countersig='^[0-9a-f]{64}\.sigstore\.json$'
bad=0
for f in "$@"; do
  n="$(basename "$f")"
  why=""
  if [[ "$n" =~ $countersig || "$n" =~ $fixed ]]; then continue; fi
  if [[ "$n" =~ r[0-9]{14} ]]; then why="a build-time stamp"
  elif [[ "$n" =~ -g[0-9a-f]{7,40}([^0-9a-z]|$) ]]; then why="a commit"
  elif [[ "$n" =~ [0-9]{8} ]]; then why="a date"
  elif ! [[ "$n" =~ $allowed ]]; then why="not an allowed name"
  fi
  if [ -n "$why" ]; then
    echo "check-names: $n: $why ($channel names: docs/release.md, File names)" >&2
    bad=1
  fi
done
[ "$bad" = 0 ] || exit 1
echo "check-names: $# $channel files, each an allowed name"
