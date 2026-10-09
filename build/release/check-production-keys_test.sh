#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# check-production-keys.sh passes a complete public key set whose
# certificates and update key say Production, and refuses a lab set, a
# certificate without Production in its CN, a Production CN that also says
# test, a set listed in the lab record, a missing file, a lab-labelled
# update key and a fingerprint record that doesn't match. An empty
# directory passes only with --allow-empty.
#
# The "fixture" key set here is made for this run in a temporary directory
# and discarded at its end; its names say fixture, never a real key.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
check="$here/check-production-keys.sh"
: > "$work/no-lab.txt"

record() { # dir
  for role in PK KEK db; do
    printf '%s %s\n' "$role" "$(openssl x509 -in "$1/$role.crt" -outform DER | sha256sum | cut -d' ' -f1)"
  done > "$1/fingerprints.txt"
  printf 'release-cosign %s\n' "$(openssl pkey -pubin -in "$1/cosign.pub" -outform DER | sha256sum | cut -d' ' -f1)" >> "$1/fingerprints.txt"
  printf 'update-recipient %s\n' "$(grep -v '^#' "$1/update.pub" | tr -d '\n' | sha256sum | cut -d' ' -f1)" >> "$1/fingerprints.txt"
}
cert() { # dir role cn
  openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 30 -subj "/CN=$3/" \
    -keyout "$1/$2.key" -out "$1/$2.crt" 2>/dev/null
}
enrol() { # dir: the lists and the signed variables, as the runbook makes them
  local d="$1" ts
  ts="$(date -u '+%Y-%m-%d %H:%M:%S')"
  for role in PK KEK db; do cert-to-efi-sig-list -g 5d4c8e4b-3b9b-4b58-9e2c-0d7e1f2a3b4c "$d/$role.crt" "$d/$role.esl"; done
  : > "$d/dbx.esl"
  sign-efi-sig-list -t "$ts" -k "$d/PK.key" -c "$d/PK.crt" PK "$d/PK.esl" "$d/PK.auth" >/dev/null
  sign-efi-sig-list -t "$ts" -k "$d/PK.key" -c "$d/PK.crt" KEK "$d/KEK.esl" "$d/KEK.auth" >/dev/null
  sign-efi-sig-list -t "$ts" -k "$d/KEK.key" -c "$d/KEK.crt" db "$d/db.esl" "$d/db.auth" >/dev/null
  sign-efi-sig-list -t "$ts" -k "$d/KEK.key" -c "$d/KEK.crt" dbx "$d/dbx.esl" "$d/dbx.auth" >/dev/null
}
expect_ok() { # what args...
  local what="$1"; shift
  out="$(LAB_RECORD="${LAB_RECORD:-$work/no-lab.txt}" bash "$check" "$@" 2>&1)" || { echo "FAIL: $what was refused: $out" >&2; exit 1; }
  echo "ok: $what"
}
expect_refused() { # what message args...
  local what="$1" msg="$2"; shift 2
  if out="$(LAB_RECORD="${LAB_RECORD:-$work/no-lab.txt}" bash "$check" "$@" 2>&1)"; then
    echo "FAIL: $what passed: $out" >&2; exit 1
  fi
  grep -q -- "$msg" <<<"$out" || { echo "FAIL: $what said: $out" >&2; exit 1; }
  echo "ok: $what is refused"
}

# A lab set, as CI makes one, and the fixture set: the same layout with
# Production names, its own cosign key and update key.
bash "$root/build/keys/lab-keys.sh" "$work/lab" >/dev/null
record "$work/lab"
mkdir -m 700 "$work/prod"
for role in PK KEK db; do cert "$work/prod" "$role" "Sneakers-PAM Production Secure Boot $role fixture"; done
enrol "$work/prod"
COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix "$work/prod/cosign" >/dev/null 2>&1
(cd "$root" && go run ./cmd/sneakers-artifact lab-update-key --name update --out "$work/prod") >/dev/null
sed -i 's/^# .*/# Sneakers-PAM Production update key fixture/' "$work/prod/update.pub" "$work/prod/update.key"
record "$work/prod"
fresh() { # name [skip]: a copy of the fixture set to break, without the files matching skip
  mkdir -m 700 "$work/$1"
  for f in "$work/prod"/*; do
    case "$(basename "$f")" in ${2:-}) continue ;; esac
    cp "$f" "$work/$1/"
  done
  echo "$work/$1"
}

expect_ok "a Production set" "$work/prod"
LAB_RECORD="$root/build/keys/lab-fingerprints.txt" expect_ok "a Production set against the committed lab record" "$work/prod"
grep -q 'check-production-keys: the production public keys pass' <<<"$out" || { echo "FAIL: pass message: $out" >&2; exit 1; }

expect_refused "a lab set" "PK.crt: the CN doesn't say Production" "$work/lab"

d="$(fresh no-prod)"
cert "$d" db "Sneakers-PAM Secure Boot db 2026"; record "$d"
expect_refused "a db.crt without Production in its CN" "db.crt: the CN doesn't say Production" "$d"

d="$(fresh test-cn)"
cert "$d" db "Sneakers-PAM Production Secure Boot db TEST"; record "$d"
expect_refused "a Production CN that also says test" "db.crt: the CN says test" "$d"

d="$(fresh dev-cn)"
cert "$d" KEK "Sneakers-PAM Production dev KEK"; record "$d"
expect_refused "a Production CN that also says dev" "KEK.crt: the CN says dev" "$d"

grep -w db "$work/prod/fingerprints.txt" | cut -d' ' -f2 > "$work/listed.txt"
LAB_RECORD="$work/listed.txt" expect_refused "a certificate in the lab record" "db.crt is a known lab key" "$work/prod"
grep -w update-recipient "$work/prod/fingerprints.txt" | cut -d' ' -f2 > "$work/listed.txt"
LAB_RECORD="$work/listed.txt" expect_refused "an update key in the lab record" "update.pub is a known lab key" "$work/prod"

d="$(fresh missing db.auth)"
expect_refused "a set without db.auth" "db.auth is missing" "$d"

d="$(fresh lab-update)"
cp "$work/lab/update.pub" "$d/update.pub"; record "$d"
expect_refused "a lab-labelled update key" "update.pub: the label doesn't say Production" "$d"

d="$(fresh stale-record)"
cert "$d" db "Sneakers-PAM Production Secure Boot db fixture"
expect_refused "a record that doesn't match the files" "db.crt is not the production fingerprint" "$d"

mkdir "$work/empty"; echo "placeholder" > "$work/empty/README.md"
expect_refused "an empty directory" "PK.crt is missing" "$work/empty"
expect_ok "an empty directory with --allow-empty" --allow-empty "$work/empty"
grep -q "no production keys committed yet" <<<"$out" || { echo "FAIL: empty message: $out" >&2; exit 1; }
d="$(fresh partial '*.auth')"
expect_refused "a partial set with --allow-empty" "PK.auth is missing" --allow-empty "$d"

# The committed lab record holds only SHA-256 values (and comments), and the
# repo's own keys/production passes as it stands (empty before the ceremony).
bad="$(grep -vE '^(#|$)' "$root/build/keys/lab-fingerprints.txt" | grep -cvE '^[0-9a-f]{64}( .*)?$' || true)"
[ "$bad" = 0 ] || { echo "FAIL: build/keys/lab-fingerprints.txt has $bad malformed lines" >&2; exit 1; }
echo "ok: the lab record is well formed"
LAB_RECORD="$root/build/keys/lab-fingerprints.txt" expect_ok "keys/production as committed" --allow-empty "$root/keys/production"
echo "PASS: check-production-keys"
