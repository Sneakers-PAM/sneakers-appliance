#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# Build a fully static cryptsetup from pinned source inside a pinned Alpine
# (musl) container. A musl-static binary is self-contained — no shared libs,
# no dynamic interpreter — which is exactly what the no-libc root image
# needs. Output: build/out/cryptsetup-<arch> and build/out/veritysetup-<arch>
# (the UKI initrd carries veritysetup; the root carries both).
#
# Requires Docker on the build host. The crypto backend is OpenSSL (>= 3.2
# provides the Argon2 KDF cryptsetup needs, so no separate libargon2).
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

if [ "$CRYPTSETUP_SHA256" = "REPLACE_WITH_VERIFIED_SHA256" ]; then
  echo "cryptsetup: set CRYPTSETUP_SHA256 in build/ci/versions.env first" >&2
  exit 1
fi

# The build runs entirely inside the pinned Alpine image; only the resulting
# static binary is copied back out to the mounted /out.
# Pass explicit values: the versions.env vars are shell-local, not exported,
# so bare `-e NAME` would forward nothing.
docker run --rm --platform "$platform" \
  -e CRYPTSETUP_VERSION="$CRYPTSETUP_VERSION" \
  -e CRYPTSETUP_SHA256="$CRYPTSETUP_SHA256" \
  -e ARCH="$arch" \
  -v "$out:/out" "$ALPINE_BUILDER" sh -eu -c '
    # -dev packages supply headers/.pc; the static .a archives come from the
    # matching -static packages (device-mapper-static, popt-static,
    # util-linux-static, openssl-libs-static). libjson-c.a ships in json-c-dev.
    apk add --no-cache \
      build-base curl xz pkgconf \
      openssl-dev openssl-libs-static \
      lvm2-dev device-mapper-static \
      popt-dev popt-static \
      json-c-dev \
      util-linux-dev util-linux-static

    cd /tmp
    short="${CRYPTSETUP_VERSION%.*}"            # 2.7.5 -> 2.7
    tb="cryptsetup-${CRYPTSETUP_VERSION}.tar.xz"
    curl -fsSL -o "$tb" \
      "https://cdn.kernel.org/pub/linux/utils/cryptsetup/v${short}/$tb"
    echo "${CRYPTSETUP_SHA256}  $tb" | sha256sum -c -
    tar xf "$tb"
    cd "cryptsetup-${CRYPTSETUP_VERSION}"

    # Static link the cryptsetup binary against the static dep graph.
    PKG_CONFIG="pkgconf --static" \
    ./configure \
      --disable-shared --enable-static \
      --enable-static-cryptsetup \
      --with-crypto_backend=openssl \
      --disable-asciidoc --disable-nls \
      --disable-ssh-token --disable-external-tokens \
      LDFLAGS="-static -s"
    make -j"$(nproc)" cryptsetup.static veritysetup.static

    for tool in cryptsetup veritysetup; do
      cp "${tool}.static" "/out/${tool}-${ARCH}"
      # Fail closed unless the result is genuinely static: a static ELF has
      # no PT_INTERP program header (no dynamic loader).
      if readelf -l "/out/${tool}-${ARCH}" | grep -q "INTERP"; then
        echo "cryptsetup: $tool is dynamically linked (has PT_INTERP)" >&2
        exit 1
      fi
      "/out/${tool}-${ARCH}" --version
    done
  '
echo "cryptsetup: wrote $out/cryptsetup-$arch and $out/veritysetup-$arch"
