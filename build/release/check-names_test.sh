#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The name check passes every allowed shape on its channel and refuses a
# date, a build-time stamp, a commit, the other channel's names and any
# shape it doesn't know.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check() { bash "$here/check-names.sh" "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

production=(
  sneakers-appliance-baseOS-0.1.0-rc.1-amd64.bin
  sneakers-appliance-baseOS-0.1.0-rc.1-amd64.bin.inputs
  sneakers-appliance-baseWeb-0.1.0-rc.1-amd64.bin
  sneakers-appliance-baseOS-patch-0.1.0-rc.1-to-0.1.0-rc.2-amd64.bin
  sneakers-appliance-baseOS-patch-0.1.0-to-0.1.1-amd64.bin.inputs
  sneakers-product-0.1.0-amd64.bin
  sneakers-product-0.1.0-rc.2-arm64.bin
  sneakers-appliance-0.1.0-rc.1-amd64.ova
  sneakers-appliance-0.1.0-rc.1-amd64.ova.sha256
  sneakers-appliance-0.1.0-rc.1-amd64.ova.sigstore.json
  sneakers-appliance-0.1.0-amd64.ova.sig
  sneakers-appliance-0.1.0-amd64.qcow2
  sneakers-appliance-0.1.0-amd64.iso
  sneakers-appliance-0.1.0-arm64.img.xz
  sneakers-product-index.json
  sneakers-product-index.json.sigstore.json
  SHA256SUMS
  SHA256SUMS.sigstore.json
  release.yaml
  release.yaml.sigstore.json
  0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9.sigstore.json
)
lab=(
  sneakers-appliance-baseOS-lab-n3-amd64.bin
  sneakers-appliance-baseOS-lab-n3-amd64.bin.inputs
  sneakers-appliance-baseWeb-lab-n3-amd64.bin
  sneakers-appliance-baseOS-patch-lab-n2-to-n3-amd64.bin
  sneakers-product-lab-sneakers.10-amd64.bin
  sneakers-appliance-lab-n3-amd64.ova
  sneakers-appliance-lab-n3-amd64.qcow2
  sneakers-appliance-lab-m-amd64.raw
  sneakers-product-index.json
  SHA256SUMS
)
check --channel production "${production[@]}" >/dev/null || fail "an allowed production name was refused"
check --channel lab "${lab[@]}" >/dev/null || fail "an allowed lab name was refused"
# The check reads the base name: a path in front is fine.
check --channel lab "/tmp/x/units/${lab[0]}" >/dev/null || fail "a path was refused"

refused() { # channel why name
  local out
  if out="$(check --channel "$1" "$3" 2>&1)"; then fail "$3 passed on $1"; fi
  grep -q "$2" <<<"$out" || fail "$3 on $1 said: $out"
}
refused production "a date" sneakers-appliance-baseOS-0.0.0-lab.20261010n3-amd64.bin
refused production "a build-time stamp" sneakers-appliance-baseOS-0.1.0-r20261010105645-amd64.bin
refused production "a commit" sneakers-appliance-baseOS-0.1.0-rc.1-ga8df881-amd64.bin
refused production "a commit" sneakers-appliance-baseWeb-0.3.2-g1a2b3c4-amd64.bin
refused lab "a build-time stamp" sneakers-appliance-baseOS-0.0.0-lab.20261010n3.r20261010105645-ga8df881-amd64-LAB.bin
refused lab "a date" sneakers-appliance-baseOS-0.0.0-lab.20261010n3-amd64-LAB.bin
refused lab "a date" sneakers-product-lab-20261010-amd64.bin
refused lab "a commit" sneakers-appliance-lab-n3-ga8df881-amd64.ova
refused production "not an allowed name" sneakers-appliance-baseOS-lab-n3-amd64.bin
refused lab "not an allowed name" sneakers-appliance-baseOS-0.1.0-rc.1-amd64.bin
refused production "not an allowed name" sneakers-0.1.0-amd64.ova
refused production "not an allowed name" sneakers-appliance-0.1.0-arm64.ova
refused production "not an allowed name" sneakers-appliance-0.1.0-amd64.vmdk
refused production "not an allowed name" sneakers-product-0.1.0-amd64-LAB.bin
refused production "not an allowed name" sneakers-appliance-0.1.0-amd64.bin
refused production "not an allowed name" notes.txt
if check --channel staging "${lab[0]}" >/dev/null 2>&1; then fail "an unknown channel passed"; fi
if check --channel lab >/dev/null 2>&1; then fail "no files passed"; fi
echo "PASS: check-names"
