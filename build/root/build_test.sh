#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh builds the same root image twice from the same inputs and
# SOURCE_DATE_EPOCH, byte for byte; the image holds exactly the declared tree
# in tree.txt, with its owners and modes; and a k0s binary or images (they
# ship in the product bundle), a missing OpenSSH or busybox, or a lab
# overlay outside a lab build or over a file the tree has, is refused, and
# so are a prebuilt input with a stale stamp and a service table that runs
# a program the root doesn't have. The OpenSSH, busybox and static tool
# inputs are stand-ins, stamped as their builds would: only their place in
# the tree is checked.
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
mkdir -p "$work/static"
for b in cryptsetup veritysetup mke2fs sgdisk watch; do printf '#!/bin/false\n# %s\n' "$b" > "$work/static/$b-amd64"; done
# shellcheck source=/dev/null
source "$here/../ci/versions.env"
for t in $TERMINFO_ENTRIES; do mkdir -p "$work/static/terminfo-amd64/${t:0:1}" && printf '%s\n' "$t" > "$work/static/terminfo-amd64/${t:0:1}/$t"; done
# shellcheck source=build/lib/stamp.sh
source "$here/../lib/stamp.sh"
busybox_stamp > "$work/busybox.stamp"
openssh_stamp > "$work/openssh/openssh.stamp"
for t in cryptsetup e2fsprogs gptfdisk procps; do static_stamp "$t" amd64 > "$work/static/$t-amd64.stamp"; done
printf '#!/bin/false\n# k0s\n' > "$work/k0s"
cat > "$work/release.yaml" <<YAML
apiVersion: sneakers-pam/v1alpha1
kind: Release
metadata:
  version: $VERSION
spec:
  kubernetes:
    k0s:
      version: test
YAML

build() { # out [env...]
  local out="$1"; shift
  env RELEASE="$work/release.yaml" OPENSSH="$work/openssh" BUSYBOX="$work/busybox" STATIC="$work/static" \
    OUT="$out" "$@" bash "$here/build.sh"
}
build "$work/a" >/dev/null
build "$work/b" >/dev/null
cmp "$work/a/root-$VERSION.img" "$work/b/root-$VERSION.img" || { echo "FAIL: two builds differ" >&2; exit 1; }
cmp "$work/a/verity.json" "$work/b/verity.json" || { echo "FAIL: verity.json differs" >&2; exit 1; }
echo "ok: two builds are byte-identical ($(stat -c %s "$work/a/root-$VERSION.img") bytes)"
# The root is uncompressed, so a delta between two releases' roots stays
# small (a patch .bin); the .bin payload carries it as it is.
sb="$(unsquashfs -s "$work/a/root-$VERSION.img")"
for part in "Inodes are uncompressed" "Data is uncompressed" "Fragments are uncompressed" "Uids/Gids (Id table) are uncompressed"; do
  grep -qF "$part" <<<"$sb" || { echo "FAIL: the root image isn't uncompressed ($part missing)" >&2; exit 1; }
done
echo "ok: the root image is uncompressed"

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
refused "k0s and the images ship in the product bundle" K0S="$work/k0s"
refused "k0s and the images ship in the product bundle" IMAGES="$work"
refused "sshd is missing (build/openssh" OPENSSH="$work/nothing"
refused "is missing (build/busybox" BUSYBOX="$work/nothing"
refused "no service table" SERVICES="$work/openssh"
refused "cryptsetup-amd64 is missing (build/static)" STATIC="$work/nothing"
mkdir -p "$work/nowatch" "$work/noterm"
cp -r "$work/static/." "$work/nowatch/" && mv "$work/nowatch/watch-amd64" "$work/nowatch/watch-amd64.away"
refused "watch-amd64 is missing (build/static)" STATIC="$work/nowatch"
cp -r "$work/static/." "$work/noterm/" && mv "$work/noterm/terminfo-amd64/x/xterm" "$work/noterm/terminfo-amd64/x/xterm.away"
refused "terminfo entry xterm is missing (build/static/procps.sh)" STATIC="$work/noterm"
mkdir -p "$work/stale"
cp "$work/busybox" "$work/stale/busybox"
printf 'busybox 1.0.0 0000\n' > "$work/stale/busybox.stamp"
refused "stale or unstamped busybox" BUSYBOX="$work/stale/busybox"
mkdir -p "$work/unstamped" && cp "$work/busybox" "$work/unstamped/busybox"
refused "stale or unstamped busybox" BUSYBOX="$work/unstamped/busybox"
mkdir -p "$work/services"
cp "$here/../../os/rootfs/services.d/"*.yaml "$work/services/"
printf 'exec: /usr/bin/not-in-the-root\nphases: [normal]\n' > "$work/services/extra.yaml"
refused "missing or not executable in the root: /usr/bin/not-in-the-root" SERVICES="$work/services"
mkdir -p "$work/overlay/etc/k0s"
printf 'x\n' > "$work/overlay/etc/k0s/k0s.yaml.tmpl"
refused "LAB_OVERLAY is for lab builds only" LAB_OVERLAY="$work/overlay"
refused "LAB_OVERLAY would replace /etc/k0s/k0s.yaml.tmpl" PINS_LDFLAGS="-X example.org/pins.Channel=lab" LAB_OVERLAY="$work/overlay"
echo "ok: k0s or images, missing OpenSSH, busybox, static tools or terminfo entries, a stale stamp, a program the root lacks, an empty service table and a misused lab overlay are refused"
