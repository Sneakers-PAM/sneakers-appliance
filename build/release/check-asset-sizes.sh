#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# check-asset-sizes.sh: refuse a release asset GitHub won't take. A GitHub
# Release asset must be under 2 GiB, so the publish job checks every file
# before it uploads any.
#
# Usage: check-asset-sizes.sh <file>...
# LIMIT (bytes, default 2 GiB) is the size no file may reach.
set -euo pipefail
limit="${LIMIT:-2147483648}"
[ "$#" -gt 0 ] || { echo "check-asset-sizes: name the files" >&2; exit 2; }
bad=0
for f in "$@"; do
  size="$(stat -c %s "$f")"
  if [ "$size" -ge "$limit" ]; then
    echo "check-asset-sizes: $(basename "$f") is $size bytes; a release asset must be under $limit" >&2
    bad=1
  fi
done
[ "$bad" = 0 ] || exit 1
echo "check-asset-sizes: $# files, each under $limit bytes"
