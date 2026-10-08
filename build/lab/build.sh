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
#   VERSION      the lab version (default 0.0.1); the build number,
#                g<the short commit>, is appended to it, git-describe style,
#                unless it already ends with it
#   K0S          the k0s binary for the product bundle (default: the K0S_VERSION
#                release from build/ci/versions.env, downloaded and checked
#                against K0S_SHA256_AMD64)
#   DISK_SIZE    the raw disk's size (default 64G)
#   KIT_MIN      the oldest kit or init version that may verify the release
#                (spec.kitMin; default 0.0.0-0, any)
#
# Output: $OUT/version (the version with the build number, which every
# file name below carries), $OUT/disk/sneakers-<version>-amd64-LAB.raw, $OUT/artifact (the
# signed OCI layout), $OUT/sneakers-kit (a kit pinned to this run's keys),
# and the lab product bundle next to them:
# $OUT/product/sneakers-product-<version>-amd64-LAB.bin with its
# sneakers-product-index.json, to upload on the Updates page or serve from
# a lab mirror. The signed UKI, $OUT/work/sneakers-<version>.efi, carries
# the lab update key (internal/ukikey), which decrypts the bundle.
#
# The lab release pins the images in build/lab/images.txt (k0s's own, the
# throwaway hello-world one and the interim edge), signs each pinned digest
# with the run's lab key, and puts them in the product bundle with k0s and
# the stacks in build/lab/stacks (docs/k0s.md). The base root carries none
# of it; it gets build/lab/overlay, the image suite's hook. Pulling the
# images needs the network.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${KERNEL:?}" "${KERNELRELEASE:?}" "${VERITYSETUP:?}" "${OPENSSH:?}" "${BUSYBOX:?}" "${KEYS:?}" "${OUT:?}"
version="${VERSION:-0.0.1}"
# Every lab artifact's name carries the commit it was built from.
build="g$(git -C "$root" rev-parse --short=7 HEAD)"
case "$version" in
  *-"$build") ;;
  *) version="$version-$build" ;;
esac
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH COSIGN_PASSWORD=""
mkdir -p "$OUT"
printf '%s\n' "$version" > "$OUT/version"
echo "lab: version $version"
work="$OUT/work"
mkdir -p "$work"

echo "lab: keys"
bash "$root/build/keys/lab-keys.sh" "$KEYS"

# shellcheck source=build/ci/versions.env
source "$root/build/ci/versions.env"
k0s="${K0S:-}"
if [ -z "$k0s" ]; then
  k0s="$work/k0s"
  echo "lab: k0s $K0S_VERSION"
  curl -fsSL --retry 3 -o "$k0s" "https://github.com/k0sproject/k0s/releases/download/${K0S_VERSION//+/%2B}/k0s-$K0S_VERSION-amd64"
  got="$(sha256sum "$k0s" | cut -d' ' -f1)"
  [ "$got" = "$K0S_SHA256_AMD64" ] || { echo "lab: k0s $K0S_VERSION has SHA-256 $got, want $K0S_SHA256_AMD64" >&2; exit 1; }
fi
k0s_sum="$(sha256sum "$k0s" | cut -d' ' -f1)"

# images.txt: <group> <name> <image> <digest>, groups k0s and thirdParty.
images=()
while read -r group name image dgst; do
  case "$group" in ''|\#*) continue ;; esac
  images+=("$group $name $image $dgst")
done < "$here/images.txt"
k0s_images="" third_party=""
for line in "${images[@]}"; do
  read -r group name image dgst <<<"$line"
  case "$group" in
    k0s) k0s_images+="        - image: $image"$'\n'"          digest: $dgst"$'\n' ;;
    thirdParty) third_party+="    $name:"$'\n'"      image: $image"$'\n'"      digest: $dgst"$'\n' ;;
    *) echo "lab: images.txt group $group (k0s or thirdParty)" >&2; exit 1 ;;
  esac
done

echo "lab: release.yaml"
cat > "$work/release.yaml" <<YAML
apiVersion: sneakers-pam/v1alpha1
kind: Release
metadata:
  version: $version
spec:
  thirdParty:
${third_party%$'\n'}
  kubernetes:
    k0s:
      version: $K0S_VERSION
      sha256:
        amd64: $k0s_sum
        arm64: $k0s_sum
      images:
${k0s_images%$'\n'}
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

echo "lab: product bundle (${#images[@]} images)"
# The lab key stands in for the org's countersignature of each pinned
# digest: it signs the manifest or index bytes, whose SHA-256 is the digest.
rm -rf "$work/images" "$work/image-sigs" "$work/manifests"
mkdir -p "$work/image-sigs" "$work/manifests"
CGO_ENABLED=0 go build -trimpath -o "$work/bundle-tool" "$root/build/tools/bundle"
for line in "${images[@]}"; do
  read -r _ _ image dgst <<<"$line"
  hexd="${dgst#sha256:}"
  "$work/bundle-tool" manifest --image "$image" --digest "$dgst" --out "$work/manifests/$hexd"
  sign_blob "$work/manifests/$hexd" "$work/image-sigs/$hexd.sigstore.json"
done
# The bundle fits the base built here, and nothing else.
VERSION="$version" CHANNEL=lab BASES="$version" RELEASE="$work/release.yaml" RELEASE_KEY="$KEYS/cosign.pub" \
  SIGNATURES="$work/image-sigs" K0S="$k0s" RECIPIENT="$KEYS/update.pub" STACKS="$here/stacks" OUT="$work/product" \
  bash "$root/build/product/build.sh"
sign_blob "$work/product/bin/header.json" "$work/product/bin/header.sigstore.json"
rm -rf "$OUT/product"
product_bin="$(go run "$root/cmd/sneakers-artifact" bin-seal --work "$work/product/bin" --bundle "$work/product/bin/header.sigstore.json" --out "$OUT/product")"
go run "$root/cmd/sneakers-artifact" product-index --out "$OUT/product/sneakers-product-index.json" "$product_bin" >/dev/null
rm -rf "$work/product/tree"

echo "lab: root"
env -u K0S -u IMAGES STATIC="${STATIC:-}" PINS_LDFLAGS="$pins" VERSION="$version" RELEASE="$work/release.yaml" OPENSSH="$OPENSSH" BUSYBOX="$BUSYBOX" \
  LAB_OVERLAY="$here/overlay" OUT="$work/root" bash "$root/build/root/build.sh"

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
go run "$root/cmd/sneakers-artifact" assemble --arch amd64 --version "$version" --channel lab --kit-min "${KIT_MIN:-0.0.0-0}" \
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
echo "lab: product bundle: the box's own check, with the key in the signed UKI"
rm -rf "$work/product-check"
go run "$root/cmd/sneakers-artifact" bin-verify --release-key "$KEYS/cosign.pub" --channel lab \
  --identity-uki "$work/sneakers-$version.efi" --extract "$work/product-check" "$product_bin"
rm -rf "$work/product-check"
echo "lab: sizes: root $(stat -c %s "$work/root/root-$version.img") bytes, product bundle $(stat -c %s "$product_bin") bytes"
echo "lab: done: $(ls "$OUT/disk") $(basename "$product_bin")"
