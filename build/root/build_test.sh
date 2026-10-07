#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh builds the same root image twice from the same inputs and
# SOURCE_DATE_EPOCH, byte for byte; the image holds exactly the declared tree
# in tree.txt, with its owners and modes; and a k0s binary that isn't the
# pinned one, a missing OpenSSH or busybox, or a lab overlay outside a lab
# build or over a file the tree has, is refused. The k0s, OpenSSH
# and busybox inputs are stand-ins: only their place in the tree is checked.
# Needs go, mksquashfs, unsquashfs and veritysetup.
#
# UPDATE=1 rewrites tree.txt from the build instead of checking it.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export SOURCE_DATE_EPOCH=1700000000 VERSION=0.0.1-test ARCH=amd64

mkdir -p "$work/openssh"
for b in sshd sshd-session sshd-auth ssh-keygen; do printf '#!/bin/false\n# %s\n' "$b" > "$work/openssh/$b"; done
printf '#!/bin/false\n# busybox\n' > "$work/busybox"
printf '#!/bin/false\n# k0s\n' > "$work/k0s"
sum="$(sha256sum "$work/k0s" | cut -d' ' -f1)"
cat > "$work/release.yaml" <<YAML
apiVersion: sneakers-pam/v1alpha1
kind: Release
metadata:
  version: $VERSION
spec:
  kubernetes:
    k0s:
      version: test
      sha256:
        amd64: $sum
        arm64: $sum
YAML

build() { # out [env...]
  local out="$1"; shift
  env RELEASE="$work/release.yaml" K0S="$work/k0s" OPENSSH="$work/openssh" BUSYBOX="$work/busybox" \
    OUT="$out" "$@" bash "$here/build.sh"
}
build "$work/a" >/dev/null
build "$work/b" >/dev/null
cmp "$work/a/root-$VERSION.img" "$work/b/root-$VERSION.img" || { echo "FAIL: two builds differ" >&2; exit 1; }
cmp "$work/a/verity.json" "$work/b/verity.json" || { echo "FAIL: verity.json differs" >&2; exit 1; }
echo "ok: two builds are byte-identical ($(stat -c %s "$work/a/root-$VERSION.img") bytes)"

# mode owner path [-> target], one per entry, from the SquashFS listing.
unsquashfs -lln "$work/a/root-$VERSION.img" |
  awk '$1 ~ /^[-dlcbps][-rwxsStT]{9}$/ { p = ""; for (i = 6; i <= NF; i++) p = p (i > 6 ? " " : "") $i; sub(/^squashfs-root/, "", p); if (p == "") p = "/"; print $1, $2, p }' |
  LC_ALL=C sort -k3 > "$work/tree.txt"
if [ -n "${UPDATE:-}" ]; then
  cp "$work/tree.txt" "$here/tree.txt"
  echo "updated: $here/tree.txt"
else
  diff -u "$here/tree.txt" "$work/tree.txt" || { echo "FAIL: the image's tree isn't tree.txt (UPDATE=1 rewrites it)" >&2; exit 1; }
  echo "ok: the image holds the declared tree"
fi
if awk '{ print $1 }' "$work/tree.txt" | grep -q '[sS]'; then echo "FAIL: a setuid or setgid entry" >&2; exit 1; fi
if awk '$2 != "0/0"' "$work/tree.txt" | grep -q .; then echo "FAIL: an entry not owned by root" >&2; exit 1; fi

refused() { # message env...
  local msg="$1" out; shift
  if out="$(build "$work/r" "$@" 2>&1)"; then echo "FAIL: built with $*" >&2; exit 1; fi
  grep -q "$msg" <<<"$out" || { echo "FAIL: $* said: $out" >&2; exit 1; }
}
printf 'other\n' > "$work/k0s-other"
refused "release.yaml pins $sum" K0S="$work/k0s-other"
refused "sshd is missing (build/openssh" OPENSSH="$work/nothing"
refused "is missing (build/busybox" BUSYBOX="$work/nothing"
refused "no service table" SERVICES="$work/openssh"
mkdir -p "$work/overlay/etc/k0s"
printf 'x\n' > "$work/overlay/etc/k0s/k0s.yaml.tmpl"
refused "LAB_OVERLAY is for lab builds only" LAB_OVERLAY="$work/overlay"
refused "LAB_OVERLAY would replace /etc/k0s/k0s.yaml.tmpl" PINS_LDFLAGS="-X example.org/pins.Channel=lab" LAB_OVERLAY="$work/overlay"
echo "ok: a wrong k0s, missing OpenSSH or busybox, an empty service table and a misused lab overlay are refused"
