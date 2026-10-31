#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# source.sh's export names the source to a sneakers-migrate that takes
# --source-name, leaves the flag off one that doesn't (the migrate image a
# release pins can be older than the first that takes it), and prints what
# the export didn't carry.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

# fake <path> <help text>: a sneakers-migrate that records its arguments.
fake() {
  cat > "$1" <<FAKE
#!/usr/bin/env bash
case "\$*" in
  *--help*) echo "$2"; exit 0 ;;
esac
printf '%s\n' "\$@" > "$scratch/args"
while [ \$# -gt 0 ]; do
  if [ "\$1" = --out ]; then : > "\$2"; fi
  shift
done
echo parity
echo "  connections 1 1"
echo "not carried: audit.audit_records (727000 rows): it stays on the source"
FAKE
  chmod +x "$1"
}

# run <migrate>: an export through source.sh.
run() {
  local work="$scratch/work"
  mkdir -p "$work"
  : > "$work/source.env"
  echo '{"SOURCE_VAULT_ROOT_KEK":"invented","SOURCE_DEV_KEK_SEED":"invented"}' > "$work/source-keys.json"
  RELEASE_SRC="$scratch" MIGRATE="$1" SYNTH=/bin/true WORK="$work" SOURCE_NAME=old-box.example.org \
    bash "$here/source.sh" export age1example "$scratch/bundle.age"
}

fake "$scratch/new" "  -N, --source-name string   the source install's box or host name"
out="$(run "$scratch/new")" || bad "the export failed: $out"
grep -qxF -- --source-name "$scratch/args" || bad "a tool that takes --source-name wasn't given it"
grep -qxF old-box.example.org "$scratch/args" || bad "the export doesn't name SOURCE_NAME"
grep -qF 'not carried: audit.audit_records (727000 rows)' <<<"$out" || bad "the export's not-carried lines aren't printed: $out"

fake "$scratch/old" "      --reset-sign-in   carry no password hash"
out="$(run "$scratch/old")" || bad "the export with an older tool failed: $out"
if grep -qxF -- --source-name "$scratch/args"; then bad "a tool without --source-name was given it"; fi

[ "$fail" = 0 ] && echo "ok: the export names the source to a tool that takes it and prints what it didn't carry"
exit "$fail"
