#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The sign job's "Seal the units (release key)" step, run as release.yml
# has it, against the directory layout the release job leaves (the unsigned
# build downloaded to $RUNNER_TEMP/unsigned, the signed artifact, the
# keyed UKI, the sealed product's work), with a fake release tool, cosign,
# go and kit, and no keys. It runs twice: the first release on a channel
# (full units only) and a release with a previous one, whose Base OS patch
# units.sh rebuilds and checks with the release's kit. Every file units.sh
# reads must be one the release layout has: a lab-only path fails here.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
wf="${WF:-$root/.github/workflows/release.yml}"
fail() { echo "FAIL: $*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# The step's script, as the runner gets it.
step="$(awk '
  $0 == "      - name: Seal the units (release key)" { on = 1; next }
  on && /^      - name: / { exit }
  on && $0 == "        run: |" { run = 1; next }
  on && run { sub(/^          /, ""); print }
' "$wf")"
[ -n "$step" ] || fail "release.yml has no \"Seal the units (release key)\" step"
grep -q 'build/lab/units\.sh' <<<"$step" || fail "the seal step doesn't run build/lab/units.sh"

# A fake sneakers-artifact: each subcommand makes what the real one does
# with the names the real one gives, so units.sh's own checks (the file
# names, SHA256SUMS) run on it as on a release. It refuses an input that
# isn't there.
mkdir -p "$tmp/bin"
cat > "$tmp/bin/fake-artifact" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cmd="$1"; shift
declare -A a=()
pos=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bridge|--previous-full-name|--previous) a["${1#--}"]=1; shift ;;
    --*) a["${1#--}"]="$2"; shift 2 ;;
    *) pos+=("$1"); shift ;;
  esac
done
need() { for f in "$@"; do [ -e "$f" ] || { echo "fake-artifact $cmd: $f isn't there" >&2; exit 1; }; done; }
case "$cmd" in
  web-pack)
    need "${a[pages]}/index.html"
    mkdir -p "${a[out]}"; echo web > "${a[out]}/web.yaml"; echo "${a[out]}/web.yaml" ;;
  web-check) need "${a[dir]}/web.yaml.sig" "${a[release-key]}" ;;
  bin-pack)
    need "${a[layout]}" "${a[recipient]}"
    mkdir -p "${a[out]}"; echo header > "${a[out]}/header.json"
    v="${a[version]}"
    case "${a[unit]}" in
      baseWeb) n="sneakers-appliance-baseWeb-$v-amd64.bin" ;;
      baseOS)
        if [ -n "${a[patch-spec]:-}" ]; then
          need "${a[patch-spec]}"
          n="sneakers-appliance-baseOS-patch-$(cat "${a[patch-spec]}")-to-$v-amd64.bin"
        else
          n="sneakers-appliance-baseOS-$v-amd64.bin"
        fi ;;
      *) echo "fake-artifact: unit ${a[unit]}" >&2; exit 1 ;;
    esac
    echo "$n" > "${a[out]}/name" ;;
  bin-seal)
    need "${a[work]}/name" "${a[bundle]}"
    mkdir -p "${a[out]}"; f="${a[out]}/$(cat "${a[work]}/name")"; echo sealed > "$f"; echo "$f" ;;
  bin-verify|patch-check)
    need "${pos[@]}" "${a[release-key]}"
    if [ -n "${a[identity-uki]:-}" ]; then need "${a[identity-uki]}"; fi
    if [ -n "${a[identity]:-}" ]; then need "${a[identity]}"; fi
    if [ -n "${a[base]:-}" ]; then need "${a[base]}"; fi
    if [ -n "${a[extract]:-}" ]; then mkdir -p "${a[extract]}"; echo layout > "${a[extract]}/index.json"; fi ;;
  patch-make)
    need "${a[base]}" "${a[target]}" "$(dirname "${a[base]}")/version"
    mkdir -p "${a[out]}/payload"; cat "$(dirname "${a[base]}")/version" > "${a[out]}/patch-spec.json" ;;
  bin-inputs) need "${pos[@]}"; printf '%064d\n' 0 ;;
  bin-name) need "${pos[@]}"; basename "${pos[0]}" ;;
  index) need "${pos[@]}"; echo '{}' > "${a[out]}" ;;
  *) echo "fake-artifact: $cmd" >&2; exit 1 ;;
esac
EOF
chmod +x "$tmp/bin/fake-artifact"
# go builds the release tool into the path it's given; cosign writes the
# bundle it's asked for.
cat > "$tmp/bin/go" <<EOF
#!/usr/bin/env bash
set -euo pipefail
[ "\$1" = build ] || { echo "fake go: \$*" >&2; exit 1; }
while [ "\$#" -gt 0 ]; do [ "\$1" = -o ] && { cp "$tmp/bin/fake-artifact" "\$2"; exit 0; }; shift; done
echo "fake go: no -o" >&2; exit 1
EOF
cat > "$tmp/bin/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = sign-blob ] || { echo "fake cosign: $*" >&2; exit 1; }
blob="${!#}"
[ -e "$blob" ] || { echo "fake cosign: $blob isn't there" >&2; exit 1; }
while [ "$#" -gt 0 ]; do [ "$1" = --bundle ] && { echo bundle > "$2"; exit 0; }; shift; done
EOF
chmod +x "$tmp/bin/go" "$tmp/bin/cosign"

# seal <previous tag or empty>: lay out what the jobs before the step leave
# and run the step.
seal() {
  local rt="$tmp/runner-${1:-first}" v=0.1.0-rc.2
  mkdir -p "$rt"
  local in="$rt/unsigned" work="$rt/work"
  mkdir -p "$in/pages" "$in/stacks/sneakers" "$work/product/bin" "$rt/keys" "$rt/signed/artifact"
  echo '<html></html>' > "$in/pages/index.html"
  echo 'k0s: pinned' > "$in/release.yaml"
  echo 'apiVersion: v1' > "$in/stacks/sneakers/a.yaml"
  printf '%064d\n' 1 > "$in/inputs-baseOS"
  # The kit, as download-artifact leaves it: no execute bit.
  cat > "$in/sneakers-kit" <<EOF
#!/usr/bin/env bash
[ "\$1" = verify ] && [ -f "\$2/index.json" ] || { echo "fake kit: \$*" >&2; exit 1; }
echo "\$2" >> "$rt/kit-verified"
EOF
  chmod 0644 "$in/sneakers-kit"
  echo layout > "$rt/signed/artifact/index.json"
  echo uki > "$work/sneakers-$v.efi"
  echo header > "$work/product/bin/header.json"
  echo "sneakers-product-$v-amd64.bin" > "$work/product/bin/name"
  cp "$tmp/bin/fake-artifact" "$rt/sneakers-artifact"
  if [ -n "$1" ]; then
    mkdir -p "$rt/previous"
    echo sealed > "$rt/previous/sneakers-appliance-baseOS-${1#v}-amd64.bin"
  fi
  local out
  if ! out="$(cd "$root" && env -i HOME="$tmp" PATH="$tmp/bin:$PATH" RUNNER_TEMP="$rt" GITHUB_SHA=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b \
    VERSION="$v" PREVIOUS="$1" RELEASE_COSIGN_KEY=fake COSIGN_PASSWORD= UPDATE_AGE_KEY=fake \
    bash --noprofile --norc -eo pipefail -c "$step" 2>&1)"; then
    fail "the seal step failed (previous '${1:-none}'): $out"
  fi
  local u="$rt/signed/units"
  for f in "sneakers-appliance-baseOS-$v-amd64.bin" "sneakers-appliance-baseWeb-$v-amd64.bin" "sneakers-product-$v-amd64.bin" \
    sneakers-product-index.json sneakers-product-index.json.sigstore.json SHA256SUMS SHA256SUMS.sigstore.json; do
    [ -f "$u/$f" ] || fail "the seal step left no $f (previous '${1:-none}'): $(ls "$u")"
  done
  if [ -n "$1" ]; then
    [ -f "$u/sneakers-appliance-baseOS-patch-${1#v}-to-$v-amd64.bin" ] || fail "no patch from $1: $(ls "$u")"
    grep -q "/patch-${1#v}/rebuilt\$" "$rt/kit-verified" 2>/dev/null || fail "the release's kit didn't verify the rebuilt patch target"
  elif ls "$u"/sneakers-appliance-baseOS-patch-* >/dev/null 2>&1; then
    fail "the first release made a patch"
  fi
  # units.sh writes its work under OUT, never into the downloaded build.
  [ ! -e "$in/units" ] && [ ! -e "$in/work" ] || fail "units.sh wrote into the unsigned build"
}
seal ""
seal v0.1.0-rc.1
echo "PASS: the release seal step, with and without a patch"
