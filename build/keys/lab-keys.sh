#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# lab-keys.sh <outdir>: make a throwaway lab key set for one CI run or test.
#
# Writes, only into <outdir>:
#   PK, KEK, db, rogue-db      .key (RSA-2048) and .crt (self-signed PEM)
#   PK.esl KEK.esl db.esl dbx.esl         EFI signature lists (dbx is empty)
#   PK.auth KEK.auth db.auth dbx.auth     time-based authenticated variables:
#                                         PK and KEK signed by PK, db and dbx by KEK
#   cosign.key cosign.pub, rogue-cosign.key rogue-cosign.pub
#                                         cosign key pairs (empty password)
#   update.key update.pub, rogue-update.key rogue-update.pub
#                                         age update keys: the .bin is
#                                         encrypted to update.pub
#
# Every subject says "LAB ephemeral NOT FOR PRODUCTION". These keys are never
# stored, published or uploaded; CI passes a fresh tmpfs directory each run.
#
# <outdir> already holding a key set is refused, so a shared on-disk lab
# folder never loses its private keys to a build that just happened to point
# at it. NEW_KEYS=1 replaces it on purpose; REUSE_KEYS=1 keeps it as is
# (refused if the set is only partial, e.g. an interrupted earlier run).
# Needs openssl, efitools (cert-to-efi-sig-list, sign-efi-sig-list), cosign and go.
set -euo pipefail

out="${1:?usage: lab-keys.sh <outdir>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for tool in openssl cert-to-efi-sig-list sign-efi-sig-list cosign go; do
  command -v "$tool" >/dev/null || { echo "lab-keys.sh: $tool is not installed" >&2; exit 3; }
done
mkdir -p "$out"
out="$(cd "$out" && pwd)"

# The full manifest this script writes (see the header above).
files=(PK.key PK.crt KEK.key KEK.crt db.key db.crt rogue-db.key rogue-db.crt
  PK.esl KEK.esl db.esl dbx.esl PK.auth KEK.auth db.auth dbx.auth
  cosign.key cosign.pub rogue-cosign.key rogue-cosign.pub
  update.key update.pub rogue-update.key rogue-update.pub)
have_any() { for f in "${files[@]}"; do [ -e "$out/$f" ] && return 0; done; return 1; }
have_all() { for f in "${files[@]}"; do [ -e "$out/$f" ] || return 1; done; return 0; }

if have_any; then
  if [ -n "${NEW_KEYS:-}" ]; then
    echo "lab-keys.sh: NEW_KEYS=1; replacing the key set in $out" >&2
    rm -f "${files[@]/#/$out/}"
  elif [ -n "${REUSE_KEYS:-}" ]; then
    have_all || { echo "lab-keys.sh: $out has a partial key set; refusing to reuse it (NEW_KEYS=1 replaces it)" >&2; exit 4; }
    echo "lab-keys.sh: REUSE_KEYS=1; reusing the key set already in $out"
    exit 0
  else
    echo "lab-keys.sh: $out already has a key set; refusing to replace it (NEW_KEYS=1 replaces it, REUSE_KEYS=1 keeps it)" >&2
    exit 4
  fi
fi

chmod 700 "$out"
umask 077
cd "$out"

# The signature-owner GUID of every list entry. Fixed so the lists are easy to
# compare between runs; it identifies the owner, not the key.
owner="5d4c8e4b-3b9b-4b58-9e2c-0d7e1f2a3b4c"
stamp="$(date -u '+%Y-%m-%d %H:%M:%S')"

for role in PK KEK db rogue-db; do
  openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
    -subj "/CN=Sneakers-PAM LAB ephemeral NOT FOR PRODUCTION ${role}/" \
    -keyout "${role}.key" -out "${role}.crt" 2>/dev/null
done

for role in PK KEK db; do
  cert-to-efi-sig-list -g "$owner" "${role}.crt" "${role}.esl"
done
: > dbx.esl

sign-efi-sig-list -t "$stamp" -k PK.key -c PK.crt PK PK.esl PK.auth >/dev/null
sign-efi-sig-list -t "$stamp" -k PK.key -c PK.crt KEK KEK.esl KEK.auth >/dev/null
sign-efi-sig-list -t "$stamp" -k KEK.key -c KEK.crt db db.esl db.auth >/dev/null
sign-efi-sig-list -t "$stamp" -k KEK.key -c KEK.crt dbx dbx.esl dbx.auth >/dev/null

for name in cosign rogue-cosign; do
  COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix "$name" >/dev/null 2>&1
done

for name in update rogue-update; do
  (cd "$root" && go run ./cmd/sneakers-artifact lab-update-key --name "$name" --out "$out") >/dev/null
done

echo "lab-keys.sh: wrote a lab key set to $out"
