#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# check-fingerprints.sh <certs-dir> <fingerprints.txt>: refuse to sign
# unless every certificate and key the sign job is about to use (PK.crt,
# KEK.crt, db.crt, the release cosign.pub and the update key recipient
# update.pub in <certs-dir>) has the production fingerprint recorded in
# keys/production/fingerprints.txt. A lab key set, or anything else, fails
# with "not the production fingerprint".
set -euo pipefail
dir="${1:?usage: check-fingerprints.sh <certs-dir> <fingerprints.txt>}"
record="${2:?usage: check-fingerprints.sh <certs-dir> <fingerprints.txt>}"
[ -s "$record" ] || { echo "check-fingerprints: $record is missing or empty" >&2; exit 1; }
want() { awk -v r="$1" '$1 == r { print $2 }' "$record"; }
fail=0
for role in PK KEK db; do
  got="$(openssl x509 -in "$dir/$role.crt" -outform DER | sha256sum | cut -d' ' -f1)"
  if [ "$got" != "$(want "$role")" ]; then
    echo "check-fingerprints: $role.crt is not the production fingerprint ($got)" >&2
    fail=1
  fi
done
got="$(openssl pkey -pubin -in "$dir/cosign.pub" -outform DER | sha256sum | cut -d' ' -f1)"
if [ "$got" != "$(want release-cosign)" ]; then
  echo "check-fingerprints: cosign.pub is not the production fingerprint ($got)" >&2
  fail=1
fi
# The recipient's fingerprint is the SHA-256 of its age1 line, the same
# value the .bin header records.
got="$(grep -v '^#' "$dir/update.pub" | tr -d '\n' | sha256sum | cut -d' ' -f1)"
if [ "$got" != "$(want update-recipient)" ]; then
  echo "check-fingerprints: update.pub is not the production fingerprint ($got)" >&2
  fail=1
fi
[ "$fail" -eq 0 ] || exit 1
echo "check-fingerprints: every certificate and key is the production one"
