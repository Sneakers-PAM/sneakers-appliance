#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# lab-keys.sh writes a fresh key set into an empty directory, refuses to
# touch a directory that already has one unless told to, and only replaces
# it with NEW_KEYS=1. REUSE_KEYS=1 accepts an existing set as is.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

hash_dir() { # dir
  find "$1" -type f -exec sha256sum {} \; | sed "s#$1/##" | LC_ALL=C sort
}

keys="$work/keys"
bash "$here/lab-keys.sh" "$keys" >/dev/null
[ -s "$keys/PK.crt" ] && [ -s "$keys/cosign.pub" ] && [ -s "$keys/update.pub" ] ||
  { echo "FAIL: an empty directory didn't get a key set" >&2; exit 1; }
echo "ok: an empty directory gets a key set"

before="$(hash_dir "$keys")"
if out="$(bash "$here/lab-keys.sh" "$keys" 2>&1)"; then
  echo "FAIL: a second run with no flag replaced the key set: $out" >&2
  exit 1
fi
grep -q "already has a key set" <<<"$out" || { echo "FAIL: wrong message: $out" >&2; exit 1; }
after="$(hash_dir "$keys")"
[ "$before" = "$after" ] || { echo "FAIL: the refused run still touched a file" >&2; exit 1; }
echo "ok: an existing key set with no flag is refused, untouched"

if out="$(REUSE_KEYS=1 bash "$here/lab-keys.sh" "$keys" 2>&1)"; then
  :
else
  echo "FAIL: REUSE_KEYS=1 refused an existing key set: $out" >&2
  exit 1
fi
after="$(hash_dir "$keys")"
[ "$before" = "$after" ] || { echo "FAIL: REUSE_KEYS=1 changed a file" >&2; exit 1; }
echo "ok: REUSE_KEYS=1 keeps an existing key set as is"

if ! out="$(NEW_KEYS=1 bash "$here/lab-keys.sh" "$keys" 2>&1)"; then
  echo "FAIL: NEW_KEYS=1 refused to replace an existing key set: $out" >&2
  exit 1
fi
after="$(hash_dir "$keys")"
[ "$before" != "$after" ] || { echo "FAIL: NEW_KEYS=1 didn't change anything" >&2; exit 1; }
echo "ok: NEW_KEYS=1 replaces an existing key set"

# REUSE_KEYS=1 against a partial key set (an interrupted run) is refused,
# not silently accepted with pieces missing.
partial="$work/partial"
mkdir -p "$partial"
cp "$keys/PK.key" "$keys/PK.crt" "$partial/"
if out="$(REUSE_KEYS=1 bash "$here/lab-keys.sh" "$partial" 2>&1)"; then
  echo "FAIL: REUSE_KEYS=1 accepted a partial key set: $out" >&2
  exit 1
fi
grep -q "partial key set" <<<"$out" || { echo "FAIL: wrong message: $out" >&2; exit 1; }
echo "ok: REUSE_KEYS=1 refuses a partial key set"

echo "PASS: lab-keys"
