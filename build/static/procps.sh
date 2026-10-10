#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# Build a fully static watch (procps-ng) for the root shell from the
# Debian-packaged source inside the pinned Debian (glibc) container, the
# same way as gptfdisk.sh. A glibc fully-static binary is self-contained (no
# PT_INTERP, no dlopen) and runs in the no-libc root image.
#
# watch draws with ncurses, which reads the terminal's description from a
# terminfo database; the root has none, so the build also copies the
# entries TERMINFO_ENTRIES names (build/ci/versions.env) from Debian's
# ncurses-base and ncurses-term, and the root build installs exactly those
# under /usr/share/terminfo.
#
# Only watch is built; the rest of procps isn't shipped. PROCPS_VERSION in
# versions.env is the upstream version the source must be.
#
# Output: build/out/watch-<arch> and build/out/terminfo-<arch>/<letter>/<name>.
# Requires Docker on the build host.
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
  -e PROCPS_VERSION="$PROCPS_VERSION" \
  -e TERMINFO_ENTRIES="$TERMINFO_ENTRIES" \
  -e ARCH="$arch" \
  -v "$out:/out" "$DEBIAN_BUILDER" sh -eu -c '
    export DEBIAN_FRONTEND=noninteractive
    echo "deb-src http://deb.debian.org/debian bookworm main" \
      >> /etc/apt/sources.list
    apt-get update >/dev/null
    # libncurses-dev carries the static libncursesw and libtinfo archives.
    apt-get install -y --no-install-recommends \
      build-essential dpkg-dev ca-certificates pkg-config \
      libncurses-dev ncurses-base ncurses-term >/dev/null
    cd /root
    apt-get source procps >/dev/null 2>&1
    srcdir="/root/procps-${PROCPS_VERSION}"
    [ -d "$srcdir" ] || { echo "procps: the source is not procps ${PROCPS_VERSION}: $(ls -d /root/procps-*/ 2>/dev/null)" >&2; exit 1; }
    cd "$srcdir"

    ./configure --disable-shared --enable-static --without-systemd \
      --disable-nls --enable-watch8bit >/dev/null
    # libtool drops a plain -static for the program; -all-static keeps it.
    make -j"$(nproc)" src/watch LDFLAGS="-all-static -s" >/dev/null

    cp src/watch "/out/watch-${ARCH}"
    if readelf -l "/out/watch-${ARCH}" | grep -q "INTERP"; then
      echo "procps: watch is dynamically linked (has PT_INTERP)" >&2
      exit 1
    fi
    "/out/watch-${ARCH}" --version | grep -qF "procps-ng ${PROCPS_VERSION}" || {
      echo "procps: watch is not procps-ng ${PROCPS_VERSION}" >&2; exit 1; }

    ti="/out/terminfo-${ARCH}"
    for t in $TERMINFO_ENTRIES; do
      first="$(printf %.1s "$t")"
      src=""
      for d in /lib/terminfo /usr/share/terminfo; do
        [ -e "$d/$first/$t" ] && { src="$d/$first/$t"; break; }
      done
      [ -n "$src" ] || { echo "procps: no terminfo entry $t" >&2; exit 1; }
      mkdir -p "$ti/$first"
      cp -L "$src" "$ti/$first/$t"
    done
  '
# shellcheck source=build/lib/stamp.sh
source "$root/build/lib/stamp.sh"
static_stamp procps "$arch" > "$out/procps-$arch.stamp"
echo "procps: wrote $out/watch-$arch and $out/terminfo-$arch"
