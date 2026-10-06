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
# Needs openssl, efitools (cert-to-efi-sig-list, sign-efi-sig-list), cosign and go.
set -euo pipefail

out="${1:?usage: lab-keys.sh <outdir>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for tool in openssl cert-to-efi-sig-list sign-efi-sig-list cosign go; do
  command -v "$tool" >/dev/null || { echo "lab-keys.sh: $tool is not installed" >&2; exit 3; }
done
mkdir -p "$out"
out="$(cd "$out" && pwd)"
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
