#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# Regenerate gen/go from proto/ with the pinned buf and protoc plugins.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
rm -rf gen/go
buf generate
