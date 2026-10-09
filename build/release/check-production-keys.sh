#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# check-production-keys.sh [--allow-empty] <dir>: refuse a production public
# key set that isn't complete, isn't labelled Production, or is a known lab
# set. It checks, in <dir>:
#   - every file in keys/production/expected-files.txt is there;
#   - PK.crt, KEK.crt and db.crt are self-signed RSA-2048 certificates whose
#     CN says Production and the role, and never lab, test, ephemeral or dev;
#   - every comment line of update.pub says Production, and none says lab,
#     test, ephemeral or dev;
#   - fingerprints.txt matches the files (build/release/check-fingerprints.sh);
#   - no certificate or key is in the lab record (LAB_RECORD, default
#     build/keys/lab-fingerprints.txt).
# With --allow-empty, a directory holding none of the expected files passes:
# the state before the owner commits the production keys.
#
# Environment: EXPECTED (default keys/production/expected-files.txt),
# LAB_RECORD (default build/keys/lab-fingerprints.txt).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
allow_empty=
if [ "${1:-}" = --allow-empty ]; then allow_empty=1; shift; fi
dir="${1:?usage: check-production-keys.sh [--allow-empty] <dir>}"
expected="${EXPECTED:-$root/keys/production/expected-files.txt}"
lab_record="${LAB_RECORD:-$root/build/keys/lab-fingerprints.txt}"
say() { echo "check-production-keys: $*" >&2; }

mapfile -t files < <(grep -vE '^(#|$)' "$expected")
[ "${#files[@]}" -gt 0 ] || { say "$expected lists no files"; exit 1; }
if [ -n "$allow_empty" ]; then
  present=0
  for f in "${files[@]}"; do [ -e "$dir/$f" ] && present=1; done
  if [ "$present" -eq 0 ]; then
    echo "check-production-keys: no production keys committed yet"
    exit 0
  fi
fi
fail=0
for f in "${files[@]}"; do
  [ -e "$dir/$f" ] || { say "$f is missing"; fail=1; }
done
[ "$fail" -eq 0 ] || exit 1

banned='(^|[^a-z])(lab|test|ephemeral|dev)([^a-z]|$)'
for role in PK KEK db; do
  crt="$dir/$role.crt"
  cn="$(openssl x509 -in "$crt" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p')"
  issuer="$(openssl x509 -in "$crt" -noout -issuer -nameopt multiline | sed -n 's/^ *commonName *= *//p')"
  if [[ "$cn" != *Production* ]]; then
    say "$role.crt: the CN doesn't say Production ($cn)"; fail=1
  elif [[ "$cn" != *" $role"* ]]; then
    say "$role.crt: the CN doesn't name $role ($cn)"; fail=1
  fi
  word="$(grep -oiE "$banned" <<<"$cn" | head -1 | tr -cd 'A-Za-z' | tr 'A-Z' 'a-z' || true)"
  [ -z "$word" ] || { say "$role.crt: the CN says $word ($cn)"; fail=1; }
  [ "$issuer" = "$cn" ] || { say "$role.crt: not self-signed (issuer $issuer)"; fail=1; }
  openssl x509 -in "$crt" -noout -text | grep -q 'Public-Key: (2048 bit)' &&
    openssl x509 -in "$crt" -noout -text | grep -q 'rsaEncryption' ||
    { say "$role.crt: not an RSA-2048 key"; fail=1; }
done

labels="$(grep '^#' "$dir/update.pub" || true)"
if [ -z "$labels" ] || grep -qv 'Production' <<<"$labels"; then
  say "update.pub: the label doesn't say Production"; fail=1
elif grep -qiE "$banned" <<<"$labels"; then
  say "update.pub: the label says lab, test, ephemeral or dev"; fail=1
fi
[ "$fail" -eq 0 ] || exit 1

bash "$here/check-fingerprints.sh" "$dir" "$dir/fingerprints.txt" >/dev/null

if [ -s "$lab_record" ]; then
  known() { grep -vE '^(#|$)' "$lab_record" | cut -d' ' -f1 | grep -qxF "$1"; }
  for role in PK KEK db; do
    fp="$(openssl x509 -in "$dir/$role.crt" -outform DER | sha256sum | cut -d' ' -f1)"
    ! known "$fp" || { say "$role.crt is a known lab key ($fp)"; fail=1; }
  done
  fp="$(openssl pkey -pubin -in "$dir/cosign.pub" -outform DER | sha256sum | cut -d' ' -f1)"
  ! known "$fp" || { say "cosign.pub is a known lab key ($fp)"; fail=1; }
  fp="$(grep -v '^#' "$dir/update.pub" | tr -d '\n' | sha256sum | cut -d' ' -f1)"
  ! known "$fp" || { say "update.pub is a known lab key ($fp)"; fail=1; }
fi
[ "$fail" -eq 0 ] || exit 1
echo "check-production-keys: the production public keys pass"
