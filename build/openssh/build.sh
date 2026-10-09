#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# Build static OpenSSH (sshd, sshd-session, sshd-auth, ssh-keygen) from the
# pinned sources in versions.env, inside the pinned Alpine (musl) builder.
# libcrypto comes from a pinned OpenSSL built in the same container; zlib,
# PAM, Kerberos and the login records are left out. The output is for the
# host's architecture (CI runs one job per arch on a native runner).
#
# Usage: build.sh [out dir]   (default: out/static)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=build/openssh/versions.env
source "$here/versions.env"

out="${1:-$root/out/static}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

case "$(uname -m)" in
  x86_64) ossl_target=linux-x86_64 ;;
  aarch64 | arm64) ossl_target=linux-aarch64 ;;
  *) echo "openssh: unsupported build host $(uname -m)" >&2; exit 1 ;;
esac

# The versions.env values are shell-local; pass each one explicitly.
docker run --rm \
  -e OPENSSH_VERSION="$OPENSSH_VERSION" -e OPENSSH_SHA256="$OPENSSH_SHA256" \
  -e OPENSSL_VERSION="$OPENSSL_VERSION" -e OPENSSL_SHA256="$OPENSSL_SHA256" \
  -e OSSL_TARGET="$ossl_target" -e OWNER="$(id -u):$(id -g)" \
  -v "$out:/out" "$ALPINE_BUILDER" sh -eu -c '
    apk add --no-cache build-base perl linux-headers curl >/dev/null
    cd /tmp

    ossl="openssl-${OPENSSL_VERSION}.tar.gz"
    curl -fsSL -o "$ossl" "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/$ossl"
    echo "${OPENSSL_SHA256}  $ossl" | sha256sum -c -
    tar xzf "$ossl"
    (
      cd "openssl-${OPENSSL_VERSION}"
      ./Configure "$OSSL_TARGET" no-shared no-module no-tests no-docs no-apps no-engine \
        --prefix=/opt/ossl --libdir=lib >/dev/null
      make -j"$(nproc)" build_libs >/dev/null
      make install_dev >/dev/null
    )

    tb="openssh-${OPENSSH_VERSION}.tar.gz"
    curl -fsSL -o "$tb" "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/$tb"
    echo "${OPENSSH_SHA256}  $tb" | sha256sum -c -
    tar xzf "$tb"
    cd "openssh-${OPENSSH_VERSION}"
    ./configure \
      --prefix=/usr --sbindir=/usr/sbin --libexecdir=/usr/libexec/openssh \
      --sysconfdir=/run/sneakers/ssh --with-pid-dir=/run/sneakers \
      --with-privsep-path=/run/sneakers/sshd-empty --with-privsep-user=sshd \
      --with-ssl-dir=/opt/ossl --without-zlib --without-pam --without-selinux \
      --without-kerberos5 --without-ldns --without-libedit \
      --disable-lastlog --disable-utmp --disable-utmpx --disable-wtmp --disable-wtmpx \
      --with-default-path=/usr/bin:/bin:/usr/sbin:/sbin \
      LDFLAGS="-static" >/dev/null
    make -j"$(nproc)" sshd sshd-session sshd-auth ssh-keygen >/dev/null
    for b in sshd sshd-session sshd-auth ssh-keygen; do
      strip "$b"
      if readelf -l "$b" | grep -q INTERP; then
        echo "openssh: $b is dynamically linked" >&2
        exit 1
      fi
      cp "$b" "/out/$b"
      chown "$OWNER" "/out/$b"
    done
  '
# shellcheck source=build/lib/stamp.sh
source "$root/build/lib/stamp.sh"
openssh_stamp > "$out/openssh.stamp"
echo "openssh: wrote $out/{sshd,sshd-session,sshd-auth,ssh-keygen}, stamped $(cat "$out/openssh.stamp")"
