#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The checker refuses a lab key set measured against another set's record,
# and passes the set its record was made from.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
record() { # dir out
  for role in PK KEK db; do
    printf '%s %s\n' "$role" "$(openssl x509 -in "$1/$role.crt" -outform DER | sha256sum | cut -d' ' -f1)"
  done > "$2"
  printf 'release-cosign %s\n' "$(openssl pkey -pubin -in "$1/cosign.pub" -outform DER | sha256sum | cut -d' ' -f1)" >> "$2"
  printf 'update-recipient %s\n' "$(grep -v '^#' "$1/update.pub" | tr -d '\n' | sha256sum | cut -d' ' -f1)" >> "$2"
}
bash "$root/build/keys/lab-keys.sh" "$work/a" >/dev/null
bash "$root/build/keys/lab-keys.sh" "$work/b" >/dev/null
record "$work/a" "$work/a.txt"
bash "$here/check-fingerprints.sh" "$work/a" "$work/a.txt" >/dev/null
if out="$(bash "$here/check-fingerprints.sh" "$work/b" "$work/a.txt" 2>&1)"; then
  echo "FAIL: another key set passed" >&2; exit 1
fi
grep -q "not the production fingerprint" <<<"$out" || { echo "FAIL: wrong message: $out" >&2; exit 1; }
# The same signing keys with another update key: the .bin would be encrypted
# to a key production boxes don't hold.
cp -r "$work/a" "$work/c"
cp "$work/a/rogue-update.pub" "$work/c/update.pub"
if out="$(bash "$here/check-fingerprints.sh" "$work/c" "$work/a.txt" 2>&1)"; then
  echo "FAIL: another update key passed" >&2; exit 1
fi
grep -q "update.pub is not the production fingerprint" <<<"$out" || { echo "FAIL: wrong message: $out" >&2; exit 1; }
# The update feed's key: a record that lists it passes the key it was made
# from, and refuses another key and a missing file.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/feed.key" 2>/dev/null
openssl pkey -in "$work/feed.key" -pubout -out "$work/a/feed.pub" 2>/dev/null
cp "$work/a.txt" "$work/f.txt"
printf 'feed-key %s\n' "$(openssl pkey -pubin -in "$work/a/feed.pub" -outform DER | sha256sum | cut -d' ' -f1)" >> "$work/f.txt"
bash "$here/check-fingerprints.sh" "$work/a" "$work/f.txt" >/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/other.key" 2>/dev/null
cp -r "$work/a" "$work/d"
openssl pkey -in "$work/other.key" -pubout -out "$work/d/feed.pub" 2>/dev/null
if out="$(bash "$here/check-fingerprints.sh" "$work/d" "$work/f.txt" 2>&1)"; then
  echo "FAIL: another feed key passed" >&2; exit 1
fi
grep -q "feed.pub is not the production fingerprint" <<<"$out" || { echo "FAIL: wrong message: $out" >&2; exit 1; }
rm "$work/d/feed.pub"
if out="$(bash "$here/check-fingerprints.sh" "$work/d" "$work/f.txt" 2>&1)"; then
  echo "FAIL: a missing feed key passed" >&2; exit 1
fi
grep -q "feed.pub is missing" <<<"$out" || { echo "FAIL: wrong message: $out" >&2; exit 1; }
echo "PASS: check-fingerprints"
