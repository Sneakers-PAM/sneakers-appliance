#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# images.sh: the release workflow's images job. It builds every Sneakers
# service image from the source release.yaml pins for it (each service's
# build block: the repository, the full commit, the Dockerfile and its
# context, the target and build args), with the repository's own
# Dockerfile, for linux/amd64, and leaves each as an OCI layout,
# OUT/<service>/. Nothing is pushed: the build job fills the digests into
# release.yaml (bundle fill), the sign job countersigns them and the publish
# job pushes them by digest.
#
# Each build is stamped with the service's version and commit (the VERSION
# and COMMIT build args the Dockerfiles take), with no provenance or SBOM
# attestation, and with SOURCE_DATE_EPOCH set to the commit's time and the
# layer timestamps rewritten to it, so the same commit builds the same
# layers.
#
# Inputs (environment):
#   RELEASE   sneakers-release's manifest/release.yaml at the pinned commit
#   OUT       the layouts directory (empty or missing)
#   BUILDER   a docker buildx builder with the docker-container driver
#             (default: one made for the run, sneakers-release-images)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${RELEASE:?}" "${OUT:?}"
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then
  echo "images: $OUT isn't empty" >&2
  exit 1
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
go run "$root/build/tools/bundle" sources --release "$RELEASE" > "$work/sources"
builder="${BUILDER:-sneakers-release-images}"
if ! docker buildx inspect "$builder" >/dev/null 2>&1; then
  docker buildx create --name "$builder" --driver docker-container >/dev/null
fi
mkdir -p "$OUT"
echo "images: $(wc -l < "$work/sources") service images to build"
while read -r name image version repo commit dockerfile context target buildargs; do
  src="$work/src/$name"
  start="$(date +%s)"
  echo "images: $name ($image $version) from $repo@$commit"
  git init -q "$src"
  git -C "$src" fetch -q --depth 1 "https://github.com/${repo}.git" "$commit"
  git -C "$src" checkout -q FETCH_HEAD
  got="$(git -C "$src" rev-parse HEAD)"
  [ "$got" = "$commit" ] || { echo "images: $repo fetched $got for $commit" >&2; exit 1; }
  epoch="$(git -C "$src" log -1 --format=%ct)"
  args=(--builder "$builder" --platform linux/amd64 --provenance=false --sbom=false
    --build-arg "VERSION=$version" --build-arg "COMMIT=$commit" --build-arg "SOURCE_DATE_EPOCH=$epoch"
    -f "$src/$dockerfile" --output "type=oci,dest=$work/$name.tar,rewrite-timestamp=true")
  [ "$target" = - ] || args+=(--target "$target")
  if [ "$buildargs" != - ]; then
    IFS=, read -r -a pairs <<<"$buildargs"
    for kv in "${pairs[@]}"; do args+=(--build-arg "$kv"); done
  fi
  SOURCE_DATE_EPOCH="$epoch" docker buildx build --progress=plain "${args[@]}" "$src/$context" > "$work/$name.log" 2>&1 \
    || { tail -40 "$work/$name.log" >&2; echo "images: $name didn't build" >&2; exit 1; }
  mkdir -p "$OUT/$name"
  tar -xf "$work/$name.tar" -C "$OUT/$name"
  rm -rf "$src" "$work/$name.tar"
  dgst="$(sed -n 's/.*"digest":"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' "$OUT/$name/index.json" | head -1)"
  echo "images: $name $dgst in $(( $(date +%s) - start ))s"
done < "$work/sources"
echo "images: built $(find "$OUT" -mindepth 1 -maxdepth 1 -type d | wc -l) images in $OUT"
