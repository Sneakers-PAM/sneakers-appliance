#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The real-bundle job's caches hold no key: build/realci/no-keys.sh finds a
# private key or a line of the run's own keys in a cached path, and the
# workflow caches only the kernel, the static tools and the service images
# (never the lab keys or the builds signed with them), checks every cached
# path with no-keys.sh before anything is saved, and keys next's images on
# their sneakers-release commit.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
check() { KEYS="$tmp/keys" bash "$here/no-keys.sh" "$@" >/dev/null 2>&1; }

mkdir -p "$tmp/keys" "$tmp/clean/sub"
printf -- '-----BEGIN %s-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END %s-----\n' "PRIVATE KEY" "PRIVATE KEY" > "$tmp/keys/db.key"
printf 'binary\0layer\n' > "$tmp/clean/sub/blob"
# A tool's code carries the markers, not a key.
printf '\0-----BEGIN %s-----\n\0%s\0' 'OPENSSH PRIVATE KEY' 'AGE-SECRET-KEY-' > "$tmp/clean/sub/ssh-keygen"
echo '{"schemaVersion":2}' > "$tmp/clean/index.json"
check "$tmp/clean" || bad "no-keys.sh refuses a path with no key in it"
check "$tmp/clean" "$tmp/missing" || bad "no-keys.sh refuses a cached path that isn't there (a skipped build)"

# case <what> <file name> <content>
case_() {
  local d="$tmp/case-$RANDOM"
  mkdir -p "$d/x"
  printf '%s\n' "$3" > "$d/x/$2"
  if check "$tmp/clean" "$d"; then bad "no-keys.sh takes $1"; fi
}
case_ "a PEM private key" k.pem "$(printf -- 'x\n-----BEGIN %s-----\nMHcCAQEE' 'EC PRIVATE KEY')"
case_ "cosign's encrypted key" k "$(printf -- '-----BEGIN %s-----' 'ENCRYPTED SIGSTORE PRIVATE KEY')"
case_ "an age identity" id.txt "$(printf '%s1QYZQYZQYZQYZQYZQYZQYZQYZQYZQYZQYZQYZQYZQYZQYZQYZQYZQYZQYZQ' 'AGE-SECRET-KEY-')"
case_ "a .key file" update.key "anything"
case_ "a line of the run's own key, out of its PEM" layer "padding MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7 padding"

# The workflow's cache paths.
wf="$root/.github/workflows/real-bundle.yml"
paths="$(awk '/uses: actions\/cache(\/restore|\/save)?@/ { c = 1; next } c && /^ *path: \|$/ { m = 1; next } c && /^ *path: / { sub(/^ *path: /, ""); print; c = 0; next } m && /^ *(key|restore-keys):/ { m = 0; c = 0 } m { gsub(/^ +/, ""); print }' "$wf")"
[ -n "$paths" ] || bad "found no cache paths in real-bundle.yml"
while read -r p; do
  case "$p" in
    *labkeys* | *'/realci'* | *'/realci-old'* | *'.key'* | *KEYS*) bad "real-bundle.yml caches $p" ;;
    build/out/* | out/static | '${{ runner.temp }}/layouts/'* | '${{ runner.temp }}/static-cache/'*) ;;
    *) bad "real-bundle.yml caches $p, which isn't a tool or image path" ;;
  esac
done <<<"$paths"
grep -q 'bash build/realci/no-keys.sh' "$wf" || bad "real-bundle.yml doesn't check its cached paths with no-keys.sh"
nk="$(grep -n 'bash build/realci/no-keys.sh' "$wf" | head -1 | cut -d: -f1)"
sv="$(grep -nE 'uses: actions/cache/save@' "$wf" | head -1 | cut -d: -f1)"
[ -n "$sv" ] && [ "$nk" -lt "$sv" ] || bad "the no-keys check doesn't run before the first save"
grep -qF "key: realci-images-next-\${{ steps.pins.outputs.next }}-" "$wf" || bad "next's images aren't keyed on their sneakers-release commit"

[ "$fail" = 0 ] && echo "ok: no-keys.sh finds keys in a cached path, and the real-bundle job caches only tools and service images, checked before they're saved"
exit "$fail"
