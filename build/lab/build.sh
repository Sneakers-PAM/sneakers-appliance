#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh: build a whole lab release and its raw disk, signed with a
# throwaway key set made for this run only, the way a pull request's image
# job does (spec 1 Section 3.8). Nothing here is ever a production key.
#
# Inputs (environment):
#   KERNEL       the bzImage (build/kernel/build.sh)
#   KERNELRELEASE its release string
#   VERITYSETUP  the static veritysetup (build/static/cryptsetup.sh)
#   OPENSSH      directory with the static sshd, sshd-session, sshd-auth and
#                ssh-keygen (build/openssh/build.sh)
#   BUSYBOX      the static busybox (build/busybox/build.sh)
#   STATIC       directory with cryptsetup-amd64, veritysetup-amd64,
#                mke2fs-amd64 and sgdisk-amd64 (build/static), which go into
#                the root; first boot needs cryptsetup and mkfs.ext4 to make
#                the state volumes
#   KEYS         an empty directory for the lab keys (CI passes a tmpfs one)
#   OUT          the output directory
#   VERSION      the lab version (default 0.0.1)
#   K0S          the k0s binary for the root (default: a stand-in, pinned in
#                the lab release.yaml, for boots that don't start k0s)
#   DISK_SIZE    the raw disk's size (default 64G)
#
# Output: $OUT/disk/sneakers-<version>-amd64-LAB.raw, $OUT/artifact (the
# signed OCI layout), $OUT/sneakers-kit (a kit pinned to this run's keys).
# The signed UKI, $OUT/work/sneakers-<version>.efi, carries the lab update
# key (internal/ukikey).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${KERNEL:?}" "${KERNELRELEASE:?}" "${VERITYSETUP:?}" "${OPENSSH:?}" "${BUSYBOX:?}" "${KEYS:?}" "${OUT:?}"
version="${VERSION:-0.0.1}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH COSIGN_PASSWORD=""
mkdir -p "$OUT"
work="$OUT/work"
mkdir -p "$work"

echo "lab: keys"
bash "$root/build/keys/lab-keys.sh" "$KEYS"

k0s="${K0S:-}"
if [ -z "$k0s" ]; then
  k0s="$work/k0s"
  printf '#!/bin/false\n# a stand-in for k0s in lab boots that never start it\n' > "$k0s"
fi
k0s_sum="$(sha256sum "$k0s" | cut -d' ' -f1)"

echo "lab: release.yaml"
cat > "$work/release.yaml" <<YAML
apiVersion: sneakers-pam/v1alpha1
kind: Release
metadata:
  version: $version
spec:
  kubernetes:
    k0s:
      version: lab
      sha256:
        amd64: $k0s_sum
        arm64: $k0s_sum
YAML
sign_blob() { # file bundle
  cosign sign-blob --yes --key "$KEYS/cosign.key" --bundle "$2" \
    --tlog-upload=false --use-signing-config=false "$1" >/dev/null 2>&1
}
sign_blob "$work/release.yaml" "$work/release.yaml.sigstore.json"

pkg=github.com/Sneakers-PAM/sneakers-appliance/internal/release
b64() { base64 -w0 < "$1"; }
pins="-X $pkg.Channel=lab -X $pkg.Version=$version \
  -X $pkg.ReleaseKey=$(b64 "$KEYS/cosign.pub") -X $pkg.DBCert=$(b64 "$KEYS/db.crt") \
  -X $pkg.PKCert=$(b64 "$KEYS/PK.crt") -X $pkg.KEKCert=$(b64 "$KEYS/KEK.crt")"

echo "lab: bundle"
# The lab release pins no images, so the bundle is empty; it's still built
# and checked the way a release's is.
rm -rf "$work/images" "$work/image-sigs"
mkdir -p "$work/image-sigs"
RELEASE="$work/release.yaml" RELEASE_KEY="$KEYS/cosign.pub" SIGNATURES="$work/image-sigs" OUT="$work/images" \
  bash "$root/build/bundle/build.sh"

echo "lab: root"
STATIC="${STATIC:-}" PINS_LDFLAGS="$pins" VERSION="$version" RELEASE="$work/release.yaml" K0S="$k0s" OPENSSH="$OPENSSH" BUSYBOX="$BUSYBOX" \
  IMAGES="$work/images" OUT="$work/root" bash "$root/build/root/build.sh"

echo "lab: UKI"
KERNEL="$KERNEL" VERITYSETUP="$VERITYSETUP" VERITY_JSON="$work/root/verity.json" \
  VERSION="$version" OUT="$work/uki" UNAME="$KERNELRELEASE" bash "$root/build/uki/assemble.sh"
# The lab update key goes into the UKI before it's signed, as the release's
# sign job does with the production one, so the box decrypts lab packages.
go run "$root/cmd/sneakers-artifact" uki-add-key --uki "$work/uki/sneakers-$version.efi" \
  --key "$KEYS/update.key" --recipient "$KEYS/update.pub" --out "$work/uki/sneakers-$version.keyed.efi" >/dev/null
sbsign --key "$KEYS/db.key" --cert "$KEYS/db.crt" --output "$work/sneakers-$version.efi" "$work/uki/sneakers-$version.keyed.efi" >/dev/null
stub=/usr/lib/systemd/boot/efi/systemd-bootx64.efi
sbsign --key "$KEYS/db.key" --cert "$KEYS/db.crt" --output "$work/systemd-bootx64.efi" "$stub" >/dev/null
systemd_version="$(dpkg-query -W -f='${Version}' systemd-boot-efi 2>/dev/null || echo unknown)"

echo "lab: artifact"
rm -rf "$OUT/artifact"
go run "$root/cmd/sneakers-artifact" assemble --arch amd64 --version "$version" --channel lab \
  --systemd "$systemd_version" --release "$work/release.yaml" --release-sig "$work/release.yaml.sigstore.json" \
  --root "$work/root/root-$version.img" --verity-json "$work/root/verity.json" \
  --uki "$work/sneakers-$version.efi" --loader "$work/systemd-bootx64.efi" --keys "$KEYS" \
  --pk-cert "$KEYS/PK.crt" --kek-cert "$KEYS/KEK.crt" --db-cert "$KEYS/db.crt" --out "$OUT/artifact"
blob="$(go run "$root/cmd/sneakers-artifact" index-blob --layout "$OUT/artifact")"
sign_blob "$blob" "$work/artifact.sigstore.json"
go run "$root/cmd/sneakers-artifact" attach --layout "$OUT/artifact" --bundle "$work/artifact.sigstore.json"

echo "lab: kit"
CGO_ENABLED=0 go build -trimpath -o "$OUT/sneakers-kit" -ldflags "-s -w $pins" "$root/cmd/sneakers-kit"

echo "lab: raw disk"
"$OUT/sneakers-kit" verify "$OUT/artifact"
mkdir -p "$OUT/disk"
"$OUT/sneakers-kit" build "$OUT/artifact" --format raw --disk-size "${DISK_SIZE:-64G}" --out "$OUT/disk"
echo "lab: done: $(ls "$OUT/disk")"
