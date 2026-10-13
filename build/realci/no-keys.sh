#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# no-keys.sh <path>...: LAB ONLY, the real-bundle job's check that nothing
# it's about to cache holds a key (docs/testing.md#the-caches): the Actions
# cache of a public repository is readable by runs from forks. It fails on
# a file named *.key, a PEM private key block (cosign's encrypted one
# among them: its BEGIN line on a line of its own), an age identity, or
# any line of the run's own private keys (KEYS/*.key, so a key copied out
# of its PEM is found too). The PEM and age markers alone, as tools such as
# ssh-keygen and cosign carry them in their code, aren't a key. A path that
# isn't there passes: its build was skipped.
set -euo pipefail
[ "$#" -gt 0 ] || { echo "usage: no-keys.sh <path>..." >&2; exit 2; }
pat="$(mktemp)"
trap 'rm -f "$pat"' EXIT
: > "$pat"
if [ -n "${KEYS:-}" ] && [ -d "$KEYS" ]; then
  # The body lines only: the PEM armour lines are matched above.
  find "$KEYS" -maxdepth 1 -type f -name '*.key' -exec grep -hv -e '^-----' -e '^$' {} + 2>/dev/null \
    | awk 'length($0) >= 16' >> "$pat" || true
fi
fail=0
for p in "$@"; do
  [ -e "$p" ] || { echo "no-keys: $p: not there"; continue; }
  this=0
  named="$(find "$p" -type f -name '*.key' | head -5)"
  [ -z "$named" ] || { echo "no-keys: $p holds key files: $named" >&2; this=1; }
  found="$({
    grep -rlaE -e '^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----$' -e 'AGE-SECRET-KEY-1[02-9ACDEFGHJKLMNPQRSTUVWXYZ]{58}' "$p" || true
    if [ -s "$pat" ]; then grep -rlaF -f "$pat" "$p" || true; fi
  } | sort -u | head -5)"
  [ -z "$found" ] || { echo "no-keys: $p holds key material: $found" >&2; this=1; }
  if [ "$this" = 1 ]; then fail=1; continue; fi
  echo "no-keys: $p: no key ($(find "$p" -type f | wc -l) files, $(du -sh "$p" | cut -f1))"
done
exit "$fail"
