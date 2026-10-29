#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# Build a fully static QEMU guest agent (qemu-ga) from the pinned QEMU
# source inside the pinned Alpine (musl) container, the same way as
# cryptsetup.sh. Only the agent is built: no emulator, no tools. The root
# image carries it on amd64 (spec 1 Section 2.8), where init runs it with
# an allow-list of RPCs (os/rootfs/services.d/qemu-ga.yaml).
#
# QEMU_VERSION and QEMU_SHA256 in build/ci/versions.env pin QEMU's release
# tarball; it's checked before it's unpacked.
#
# Output: build/out/qemu-ga-<arch>. Requires Docker on the build host.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=/dev/null
source "$root/build/ci/versions.env"

arch="${1:-amd64}"
out="$root/build/out"
mkdir -p "$out"

case "$arch" in
  amd64) platform=linux/amd64 ;;
  arm64) platform=linux/arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

# versions.env vars are shell-local (not exported), so pass them with -e.
docker run --rm --platform "$platform" \
  -e QEMU_VERSION="$QEMU_VERSION" \
  -e QEMU_SHA256="$QEMU_SHA256" \
  -e ARCH="$arch" \
  -v "$out:/out" "$ALPINE_BUILDER" sh -eu -c '
    # QEMU configures with meson from its own bundled wheels, in a venv
    # made with the system setuptools, wheel and pip (nothing from PyPI);
    # glib-static and its static dependencies give the agent its only
    # library.
    apk add --no-cache \
      build-base curl xz pkgconf python3 py3-setuptools py3-wheel py3-pip \
      samurai bash perl flex bison \
      glib-dev glib-static pcre2-dev libffi-dev \
      zlib-dev zlib-static gettext-dev gettext-static linux-headers >/dev/null

    cd /tmp
    tb="qemu-${QEMU_VERSION}.tar.xz"
    curl -fsSL -o "$tb" "https://download.qemu.org/$tb" # scrub:allow=fqdn -- the QEMU release download site
    echo "${QEMU_SHA256}  $tb" | sha256sum -c -
    tar xf "$tb"
    cd "qemu-${QEMU_VERSION}"

    ./configure --static --without-default-features --enable-guest-agent \
      --disable-system --disable-user --disable-tools --disable-docs \
      --disable-werror --disable-download >/dev/null
    ninja -C build qga/qemu-ga >/dev/null

    strip -o "/out/qemu-ga-${ARCH}" build/qga/qemu-ga
    if readelf -l "/out/qemu-ga-${ARCH}" | grep -q "INTERP"; then
      echo "qemu-ga: the agent is dynamically linked (has PT_INTERP)" >&2
      exit 1
    fi
    "/out/qemu-ga-${ARCH}" --version | grep -qF "QEMU Guest Agent ${QEMU_VERSION}" || {
      echo "qemu-ga: the agent is not QEMU ${QEMU_VERSION}: $("/out/qemu-ga-${ARCH}" --version)" >&2; exit 1; }
    # The allow-list in qemu-ga.yaml must name only RPCs this build has.
    "/out/qemu-ga-${ARCH}" --allow-rpcs=help > "/out/qemu-ga-${ARCH}.rpcs"
  '
# Every RPC the service table allows is one this build has.
allowed="$(sed -n 's/^ *- --allow-rpcs=//p' "$root/os/rootfs/services.d/qemu-ga.yaml")"
[ -n "$allowed" ] || { echo "qemu-ga: os/rootfs/services.d/qemu-ga.yaml has no --allow-rpcs" >&2; exit 1; }
for rpc in ${allowed//,/ }; do
  grep -qxF "$rpc" "$out/qemu-ga-$arch.rpcs" || { echo "qemu-ga: the allowed RPC $rpc isn't in QEMU $QEMU_VERSION's agent" >&2; exit 1; }
done
# shellcheck source=build/lib/stamp.sh
source "$root/build/lib/stamp.sh"
static_stamp qemu-ga "$arch" > "$out/qemu-ga-$arch.stamp"
echo "qemu-ga: wrote $out/qemu-ga-$arch"
