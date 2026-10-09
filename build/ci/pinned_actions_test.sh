#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# Every action a workflow uses is pinned to a full commit, with the tag it
# was taken from in a comment ("uses: owner/repo@<40 hex>  # v1.2.3"), so a
# moved tag can't change what runs. They're bumped by hand. The org's own
# reusable workflows (Sneakers-PAM/.github) and local actions (./) are
# exempt: they follow the org's main on purpose.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

# check <dir>: every workflow in dir passes, or each offender is named.
check() {
  local dir="$1" bad=0 line file rest n use ref
  while IFS= read -r line; do
    file="${line%%:*}" rest="${line#*:}" n="${rest%%:*}" use="${rest#*:}"
    ref="$(sed -E 's/^[[:space:]-]*uses:[[:space:]]*//; s/[[:space:]].*$//' <<<"$use")"
    case "$ref" in ./* | Sneakers-PAM/.github/*) continue ;; esac
    if ! [[ "$use" =~ uses:[[:space:]]*[^@[:space:]]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9][^[:space:]]*[[:space:]]*$ ]]; then
      echo "FAIL: $(basename "$file"):$n: $ref isn't pinned to a full commit with its tag in a comment" >&2
      bad=1
    fi
  done < <(grep -nE '^[[:space:]-]*uses:' "$dir"/*.y*ml /dev/null)
  return "$bad"
}

# The check itself: a tag, a short commit and a commit without its tag fail;
# a pinned action, a local one and the org's reusable workflow pass.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/ok" "$work/bad"
cat > "$work/ok/a.yml" <<'YAML'
jobs:
  a:
    uses: Sneakers-PAM/.github/.github/workflows/scrub.yml@main
  b:
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262  # v4.4.0
      - uses: ./local
YAML
check "$work/ok" || { echo "FAIL: the pinned fixture was refused" >&2; exit 1; }
for use in actions/checkout@v4 actions/checkout@11d5960 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262'; do
  printf 'jobs:\n  a:\n    steps:\n      - uses: %s\n' "$use" > "$work/bad/a.yml"
  if check "$work/bad" 2>/dev/null; then echo "FAIL: $use passed" >&2; exit 1; fi
done

check "${WORKFLOWS:-$root/.github/workflows}" || exit 1
echo "PASS: every action is pinned to a commit"
