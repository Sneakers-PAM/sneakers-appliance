#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check the static OpenSSH and busybox outputs: static, the pinned version,
# and busybox without network daemons (nc only as a client).
#
# Usage: test.sh <out dir>
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=build/openssh/versions.env
source "$here/versions.env"
out="${1:?out dir}"

for b in sshd sshd-session sshd-auth ssh-keygen busybox; do
  [ -x "$out/$b" ] || { echo "missing: $b"; exit 1; }
  if readelf -l "$out/$b" | grep -q INTERP; then
    echo "not static: $b"
    exit 1
  fi
done
"$out/sshd" -V 2>&1 | grep -q "OpenSSH_${OPENSSH_VERSION}" || { echo "wrong sshd version"; exit 1; }
"$out/ssh-keygen" -t ed25519 -N '' -q -f "$(mktemp -d)/k" || { echo "ssh-keygen can't make a key"; exit 1; }
applets="$("$out/busybox" --list)"
grep -qx sh <<<"$applets" || { echo "busybox has no sh"; exit 1; }
for daemon in telnetd httpd ftpd tftpd inetd udhcpd dnsd ntpd sshd crond syslogd; do
  if grep -qx "$daemon" <<<"$applets"; then
    echo "busybox carries a network daemon: $daemon"
    exit 1
  fi
done
# nc is there for port checks (nc -z) and is built without its server, so
# it can't listen.
if grep -qx nc <<<"$applets" && timeout 5 "$out/busybox" nc -l -p 1 </dev/null >/dev/null 2>&1; then
  echo "busybox's nc can listen"
  exit 1
fi
for want in ls ps top ip netstat vi less mount dmesg; do
  grep -qx "$want" <<<"$applets" || { echo "busybox has no $want"; exit 1; }
done
echo "static tools: ok"
