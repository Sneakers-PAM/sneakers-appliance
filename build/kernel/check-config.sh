#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# check-config.sh <.config> <required.txt>: fail, listing every miss, unless
# each required option has its required value. "=n" means "is not set".
set -euo pipefail
config="${1:?usage: check-config.sh <.config> <required.txt>}"
required="${2:?usage: check-config.sh <.config> <required.txt>}"
missing=0
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  key="${line%%=*}"
  want="${line#*=}"
  if [ "$want" = "n" ]; then
    if grep -q "^${key}=" "$config"; then
      echo "check-config: $key must not be set" >&2
      missing=$((missing + 1))
    fi
  elif ! grep -qx "${key}=${want}" "$config"; then
    echo "check-config: $key=$want is missing" >&2
    missing=$((missing + 1))
  fi
done < "$required"
if [ "$missing" -gt 0 ]; then
  echo "check-config: $missing required option(s) missing" >&2
  exit 1
fi
echo "check-config: every required option is set"
