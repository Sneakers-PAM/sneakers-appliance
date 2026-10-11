#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# unphased.sh STACKS OUT: LAB ONLY. The lab stacks as a product without
# phases had them (build/lab/product-unphased.yaml): the phases' workloads
# go into the hello stack, lab-mcp keeps its own, and no workload carries
# a phase label.
set -euo pipefail
in="${1:?the lab stacks}"
out="${2:?the output directory}"
strip() { grep -v 'sneakers-appliance/phase' "$1"; }
mkdir -p "$out/hello" "$out/lab-mcp" "$out/edge"
{
  strip "$in/hello/hello.yaml"
  for f in "$in/lab-data/lab-data.yaml" "$in/lab-front/lab-front.yaml"; do
    echo "---"
    strip "$f"
  done
} > "$out/hello/hello.yaml"
strip "$in/lab-mcp/lab-mcp.yaml" > "$out/lab-mcp/lab-mcp.yaml"
cp "$in/edge/edge.yaml" "$out/edge/edge.yaml"
