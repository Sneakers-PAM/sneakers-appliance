#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The Image E2E suite runs only on main (after each merge, nightly and on
# demand), and takes about 20 minutes. A newer pull request push may cancel
# its pull request's run, but a merge must never cancel the suite already
# running on main, or merges closer together than a run never get a result.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
wf="$here/../../.github/workflows/image-e2e.yml"
line="$(grep -E '^[[:space:]]+cancel-in-progress:' "$wf" | head -1 | sed -E 's/^[[:space:]]+cancel-in-progress:[[:space:]]*//')"
case "$line" in
  "\${{ github.event_name == 'pull_request' }}") echo "ok: the Image E2E suite on main is never cancelled by a newer merge" ;;
  *) echo "FAIL: image-e2e.yml cancel-in-progress is '$line'; a merge would cancel the suite running on main" >&2; exit 1 ;;
esac
