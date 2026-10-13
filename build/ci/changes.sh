#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# changes.sh <event>: reads a pull request's changed paths, one per line, and
# prints what they need, as key=value lines for $GITHUB_OUTPUT:
#
#   docs_only  every path is documentation (*.md, docs/**)
#   yaml       a YAML file (or the yamllint config) changed
#   workflows  a workflow or a local action changed
#
# Anything that isn't a pull request, or an empty list, runs everything.
set -euo pipefail
event="${1:?usage: changes.sh <event>}"
if [ "$event" != pull_request ]; then
  printf 'docs_only=false\nyaml=true\nworkflows=true\n'
  exit 0
fi
any=false docs=true yaml=false workflows=false
while IFS= read -r p; do
  [ -n "$p" ] || continue
  any=true
  case "$p" in
    *.md | docs/*) ;;
    *) docs=false ;;
  esac
  case "$p" in *.yml | *.yaml | .yamllint) yaml=true ;; esac
  case "$p" in .github/workflows/* | .github/actions/*) workflows=true ;; esac
done
if [ "$any" = false ]; then
  printf 'docs_only=false\nyaml=true\nworkflows=true\n'
  exit 0
fi
printf 'docs_only=%s\nyaml=%s\nworkflows=%s\n' "$docs" "$yaml" "$workflows"
