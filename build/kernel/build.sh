#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh [amd64]: fetch the pinned kernel from its stable git tag, merge
# os/kernel/config-base and every platform profile onto tinyconfig, check the
# result, and build a reproducible bzImage. One kernel serves every amd64
# platform, because one signed UKI does. Output: build/out/kernel/<arch>/bzImage
# and its .config.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=build/ci/versions.env
source "$root/build/ci/versions.env"

arch="${1:-amd64}"
out="$root/build/out/kernel/$arch"
work="$root/build/.work/kernel"
mkdir -p "$out" "$work"

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH KBUILD_BUILD_TIMESTAMP="@$SOURCE_DATE_EPOCH"
export KBUILD_BUILD_USER=sneakers KBUILD_BUILD_HOST=sneakers KBUILD_BUILD_VERSION=1

src="$work/linux-${KERNEL_VERSION}"
if [ ! -d "$src" ]; then
  git clone -q --depth 1 --branch "v${KERNEL_VERSION}" \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git "$src"
fi
got="$(git -C "$src" rev-parse HEAD)"
[ "$got" = "$KERNEL_COMMIT" ] || { echo "kernel: v$KERNEL_VERSION is $got, want the pinned $KERNEL_COMMIT" >&2; exit 1; }

case "$arch" in
  amd64) karch=x86_64; profiles=(vmware qemu proxmox) ;;
  *) echo "kernel: unsupported arch $arch (arm64 comes with the Pi build)" >&2; exit 1 ;;
esac

make -s -C "$src" ARCH="$karch" tinyconfig
fragments=("$root/os/kernel/config-base")
for p in "${profiles[@]}"; do fragments+=("$root/os/kernel/profiles/$p.config"); done
"$src/scripts/kconfig/merge_config.sh" -m -O "$src" "$src/.config" "${fragments[@]}" >/dev/null
make -s -C "$src" ARCH="$karch" olddefconfig

# Every requested =y must survive the merge: an unmet dependency makes
# olddefconfig drop it silently.
dropped=""
for frag in "${fragments[@]}"; do
  while IFS= read -r opt; do
    key="${opt%%=*}"
    grep -q "^${key}=y" "$src/.config" || dropped="$dropped $key"
  done < <(grep -E '^CONFIG_[A-Z0-9_]+=y' "$frag")
done
if [ -n "$dropped" ]; then
  echo "kernel: requested options dropped from .config (unmet dependencies):$dropped" >&2
  exit 1
fi
bash "$here/check-config.sh" "$src/.config" "$root/os/kernel/required.txt"

make -s -C "$src" ARCH="$karch" -j"$(nproc)" bzImage
cp "$src/arch/$karch/boot/bzImage" "$out/bzImage"
cp "$src/.config" "$out/.config"
make -s -C "$src" ARCH="$karch" kernelrelease > "$out/kernelrelease"
sha256sum "$out/bzImage"
echo "kernel: wrote $out/bzImage ($(cat "$out/kernelrelease"))"
