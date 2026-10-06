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
echo "PASS: check-fingerprints"
