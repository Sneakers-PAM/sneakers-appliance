#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The size check passes files under the limit and refuses one at it.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
printf '123456789' > "$work/small.bin"
printf '1234567890' > "$work/at-limit.bin"
LIMIT=10 bash "$here/check-asset-sizes.sh" "$work/small.bin" >/dev/null
if out="$(LIMIT=10 bash "$here/check-asset-sizes.sh" "$work/small.bin" "$work/at-limit.bin" 2>&1)"; then
  echo "FAIL: a file at the limit passed" >&2; exit 1
fi
grep -q "at-limit.bin is 10 bytes" <<<"$out" || { echo "FAIL: wrong message: $out" >&2; exit 1; }
if bash "$here/check-asset-sizes.sh" >/dev/null 2>&1; then
  echo "FAIL: no files passed" >&2; exit 1
fi
echo "PASS: check-asset-sizes"
