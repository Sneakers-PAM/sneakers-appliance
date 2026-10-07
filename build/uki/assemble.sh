#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# assemble.sh: build the unsigned UKI (systemd-stub with ukify) for one
# release. The initrd holds only sneakers-switchroot and a static
# veritysetup; the root lives in its own verity partition, named by the
# signed command line.
#
# Inputs (environment):
#   KERNEL        the kernel image (bzImage)
#   VERITYSETUP   the static veritysetup binary
#   VERITY_JSON   verity.json from the root build: {"roothash": ..., "hashOffset": ...}
#   VERSION       the release version
#   OUT           the output directory (sneakers-<version>.efi goes there)
#   ARCH          amd64 (default)
#   UNAME         the kernel release string (default: read from the kernel build)
#   SOURCE_DATE_EPOCH  defaults to the last commit's time, for a reproducible image
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${KERNEL:?}" "${VERITYSETUP:?}" "${VERITY_JSON:?}" "${VERSION:?}" "${OUT:?}"
arch="${ARCH:-amd64}"
uname_r="${UNAME:?set UNAME to the kernel release}"

roothash="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["roothash"])' "$VERITY_JSON")"
hashoffset="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hashOffset"])' "$VERITY_JSON")"
[[ "$roothash" =~ ^[0-9a-f]{64}$ ]] || { echo "uki: bad roothash in $VERITY_JSON" >&2; exit 1; }
[[ "$hashoffset" =~ ^[0-9]+$ ]] || { echo "uki: bad hashOffset in $VERITY_JSON" >&2; exit 1; }

# The command line of spec 1 Section 3.3. Only the signed UKI carries it.
cmdline="sneakers.roothash=$roothash sneakers.hashoffset=$hashoffset sneakers.version=$VERSION quiet console=tty0 console=ttyS0 panic=10 lockdown=integrity dummy.numdummies=0"

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/initrd/usr/sbin" "$OUT"
GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$work/initrd/init" "$root/cmd/sneakers-switchroot"
install -m 0755 "$VERITYSETUP" "$work/initrd/usr/sbin/veritysetup"
find "$work/initrd" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
( cd "$work/initrd" && find . -print0 | sort -z \
    | cpio --null --create --format=newc --owner=0:0 --reproducible 2>/dev/null \
    | gzip -n ) > "$work/initrd.cpio.gz"

# SBAT: the shim generation line, then the appliance's own generation,
# starting at 1, so a bad release can be revoked by generation later.
cat > "$work/sbat.csv" <<SBAT
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
sneakers-pam,1,Sneakers-PAM,sneakers-appliance,$VERSION,https://github.com/Sneakers-PAM/sneakers-appliance
SBAT

# ukify is a python3 script; a python3 earlier on PATH (a virtualenv, pyenv)
# may lack pefile, so run it under the system interpreter and check first.
ukify_python=/usr/bin/python3
ukify_bin="$(command -v ukify)" || { echo "uki: ukify not found (install systemd-ukify)" >&2; exit 1; }
"$ukify_python" -c 'import pefile' 2>/dev/null || { echo "uki: $ukify_python can't import pefile (install python3-pefile)" >&2; exit 1; }

out="$OUT/sneakers-$VERSION.efi"
"$ukify_python" "$ukify_bin" build \
  --linux="$KERNEL" \
  --initrd="$work/initrd.cpio.gz" \
  --cmdline="$cmdline" \
  --os-release="@$here/os-release" \
  --uname="$uname_r" \
  --sbat="@$work/sbat.csv" \
  --output="$out"

# Exactly the six sections, or the box couldn't predict PCR 11 for it.
go run "$root/build/uki/check" "$out"
echo "uki: wrote $out (unsigned)"
