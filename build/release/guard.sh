#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# guard.sh: the release workflow's first job. It decides the channel and the
# version, and refuses to start a production release that can't be right.
#
# Inputs (environment):
#   EVENT          the workflow event: push (a v tag) or workflow_dispatch (a lab dry run)
#   REF_NAME       the tag (push)
#   COMMIT         the commit being released
#   INPUT_VERSION  the lab version (workflow_dispatch)
#   MAIN_REF       main's ref (default origin/main)
#   FINGERPRINTS   the production key record (default keys/production/fingerprints.txt)
#   PINS_ENV       the release pins (default build/release/pins.env)
#   GITHUB_OUTPUT  where version= and channel= are written
set -euo pipefail
: "${EVENT:?}" "${COMMIT:?}" "${GITHUB_OUTPUT:?}"
main_ref="${MAIN_REF:-origin/main}"
fingerprints="${FINGERPRINTS:-keys/production/fingerprints.txt}"
pins="${PINS_ENV:-build/release/pins.env}"
semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$'

case "$EVENT" in
  push)
    tag="${REF_NAME:-}"
    version="${tag#v}"
    if [[ "$tag" != v* ]] || ! [[ "$version" =~ $semver ]]; then
      echo "guard: $tag isn't a release tag (v<major>.<minor>.<patch>[-pre])" >&2; exit 1
    fi
    if ! git merge-base --is-ancestor "$COMMIT" "$main_ref"; then
      echo "guard: the tag's commit $COMMIT isn't on main" >&2; exit 1
    fi
    if [ ! -s "$fingerprints" ]; then
      echo "guard: $fingerprints is missing; the owner commits the production public keys first (docs/runbooks/production-keys.md)" >&2; exit 1
    fi
    pin="$(sed -n 's/^SNEAKERS_RELEASE_VERSION=//p' "$pins")"
    if [ -z "$pin" ]; then
      echo "guard: SNEAKERS_RELEASE_VERSION in $pins is empty; pin the sneakers-release version this release is built for" >&2; exit 1
    fi
    channel=production
    ;;
  workflow_dispatch)
    version="${INPUT_VERSION:-}"
    if ! [[ "$version" =~ $semver ]]; then
      echo "guard: $version isn't a lab version (<major>.<minor>.<patch>[-pre])" >&2; exit 1
    fi
    channel=lab
    ;;
  *)
    echo "guard: the release workflow doesn't run on $EVENT" >&2; exit 1
    ;;
esac
{
  echo "version=$version"
  echo "channel=$channel"
} >> "$GITHUB_OUTPUT"
echo "guard: $channel release $version from $COMMIT"
