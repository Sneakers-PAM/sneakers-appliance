#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# stamp.sh (sourced): what each prebuilt input of the root image is stamped
# with when it's built, and the check the root build makes before it uses
# one. A stamp names the tool, its pinned version and the SHA-256 of
# everything that decides the build (the pins, the config, the build
# script), so a binary left from an older pin or config is refused instead
# of shipping (docs/building.md#prebuilt-inputs).

stamp_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# stamp_of <name> <version> <file>...: the stamp line.
stamp_of() {
  local name="$1" ver="$2"
  shift 2
  printf '%s %s %s\n' "$name" "$ver" "$(cat "$@" | sha256sum | cut -d' ' -f1)"
}

# busybox_stamp: a busybox from build/busybox at the current pins and
# config.
busybox_stamp() {
  local v
  v="$(sed -n 's/^BUSYBOX_VERSION=//p' "$stamp_root/build/openssh/versions.env")"
  stamp_of busybox "$v" "$stamp_root/build/openssh/versions.env" "$stamp_root/build/busybox/busybox.config" "$stamp_root/build/busybox/build.sh"
}

# openssh_stamp: the static OpenSSH from build/openssh at the current pins.
openssh_stamp() {
  local v
  v="$(sed -n 's/^OPENSSH_VERSION=//p' "$stamp_root/build/openssh/versions.env")"
  stamp_of openssh "$v" "$stamp_root/build/openssh/versions.env" "$stamp_root/build/openssh/build.sh"
}

# static_stamp <cryptsetup|e2fsprogs|gptfdisk|procps> <arch>: a static tool from
# build/static at the current pins.
static_stamp() {
  stamp_of "$1-$2" pinned "$stamp_root/build/ci/versions.env" "$stamp_root/build/static/$1.sh"
}

# stamp_check <stamp file> <expected line> <what>: refuse a prebuilt input
# whose stamp is missing or isn't the current one.
stamp_check() {
  local got=""
  [ -s "$1" ] && got="$(head -n 1 "$1")"
  if [ "$got" != "$2" ]; then
    echo "stale or unstamped $3: $1 says '${got:-nothing}', the current pins and config give '$2'; build it again" >&2
    return 1
  fi
}
