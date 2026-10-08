#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# Rebuild internal/credentials/breached.bin, the breached-password list the
# box checks new passwords against, from two pinned SecLists files (MIT).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
rev=47cd752f4323f703e304104173633ee31462b9b3
base="https://raw.githubusercontent.com/danielmiessler/SecLists/${rev}/Passwords/Common-Credentials"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fetch() {
  curl -sSfL -o "$work/$1" "$base/$1"
  echo "$2  $work/$1" | sha256sum -c --quiet
}
fetch xato-net-10-million-passwords-1000000.txt 424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51
fetch 100k-most-used-passwords-NCSC.txt c2e5696882c603b76bb67a47ee970897e5a76fc4c3f5547abe3d0ca340c576e0
go run ./build/tools/breached internal/credentials/breached.bin "$work"/*.txt
