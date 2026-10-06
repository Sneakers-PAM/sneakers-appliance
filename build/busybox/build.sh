#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# Build a static busybox from the pinned source, inside the pinned Alpine
# (musl) builder. Only the applets busybox.config turns on are built:
# the elevation shell and the support tools, never a network daemon.
#
# Usage: build.sh [out dir]   (default: out/static)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=build/openssh/versions.env
source "$root/build/openssh/versions.env"

out="${1:-$root/out/static}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

docker run --rm \
  -e BUSYBOX_VERSION="$BUSYBOX_VERSION" -e BUSYBOX_SHA256="$BUSYBOX_SHA256" \
  -e OWNER="$(id -u):$(id -g)" \
  -v "$out:/out" -v "$here/busybox.config:/busybox.config:ro" "$ALPINE_BUILDER" sh -eu -c '
    apk add --no-cache build-base linux-headers curl >/dev/null
    cd /tmp
    tb="busybox-${BUSYBOX_VERSION}.tar.bz2"
    curl -fsSL -o "$tb" "https://busybox.net/downloads/$tb"
    echo "${BUSYBOX_SHA256}  $tb" | sha256sum -c -
    tar xjf "$tb"
    cd "busybox-${BUSYBOX_VERSION}"
    # Start from nothing and turn on only what the fragment lists; every
    # option it does not name stays off.
    make allnoconfig >/dev/null 2>&1
    while IFS= read -r line; do
      case "$line" in "" | "#"*) continue ;; esac
      sym="${line%%=*}"
      sed -i "/^# ${sym} is not set\$/d; /^${sym}=/d" .config
      echo "$line" >> .config
    done < /busybox.config
    yes "" | make oldconfig >/dev/null 2>&1
    for want in $(grep -v "^#" /busybox.config | grep "=y$" | cut -d= -f1); do
      grep -qx "${want}=y" .config || { echo "busybox: $want did not stick" >&2; exit 1; }
    done
    make -j"$(nproc)" busybox >/dev/null
    strip busybox
    if readelf -l busybox | grep -q INTERP; then
      echo "busybox: dynamically linked" >&2
      exit 1
    fi
    cp busybox /out/busybox
    cp .config /out/busybox.config.full
    chown "$OWNER" /out/busybox /out/busybox.config.full
  '
echo "busybox: wrote $out/busybox"
