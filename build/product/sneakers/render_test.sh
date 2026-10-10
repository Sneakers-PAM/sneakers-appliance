#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The production product bundle's stacks, rendered by render.sh from
# sneakers-release's charts, are complete and carry nothing of a lab build:
#
#   - every component product.yaml names is pinned in release.yaml, every
#     service image release.yaml pins runs in a stack, the migrate Job image
#     is pinned and the main stack lists the migrate caller;
#   - every container runs an image pinned by digest, never pulled;
#   - no stack carries a Secret (each box makes its own), and every
#     Secret a workload reads is a box secret product.yaml declares
#     (build/tools/stack refuses otherwise);
#   - no lab value: no lab registry or host, no debug or console logging, no
#     dev-only switch, no "lab" in a name or value;
#   - render.sh refuses a non-empty OUT, and a values overlay that brings
#     a Secret no box makes.
#
# CHARTS is a sneakers-release checkout; without it the test fetches the
# commit build/release/pins.env pins (or main while that's empty). The
# service digests, placeholders in git, are filled with stand-ins here.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

charts="${CHARTS:-}"
if [ -z "$charts" ]; then
  # shellcheck source=build/release/pins.env
  source "$root/build/release/pins.env"
  charts="$work/sneakers-release"
  git init -q "$charts"
  git -C "$charts" fetch -q --depth 1 "https://github.com/${SNEAKERS_RELEASE_REPO}.git" "${SNEAKERS_RELEASE_COMMIT:-main}"
  git -C "$charts" checkout -q FETCH_HEAD
fi
helm="${HELM:-}"
if [ -z "$helm" ]; then
  # shellcheck source=build/ci/versions.env
  source "$root/build/ci/versions.env"
  curl -fsSL --retry 3 -o "$work/helm.tar.gz" "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz"
  [ "$(sha256sum < "$work/helm.tar.gz" | cut -d' ' -f1)" = "$HELM_TGZ_SHA256_AMD64" ] || fail "helm $HELM_VERSION isn't the pinned tarball"
  tar -xzOf "$work/helm.tar.gz" linux-amd64/helm > "$work/helm"
  chmod 0755 "$work/helm"
  helm="$work/helm"
fi

# A stand-in digest for each service image, as bundle fill leaves them.
n=0
while IFS= read -r line; do
  if [[ "$line" == *"sha256:TBD-at-release"* ]]; then
    n=$((n + 1))
    line="${line/sha256:TBD-at-release/sha256:$(printf '%064x' "$n")}"
  fi
  printf '%s\n' "$line"
done < "$charts/manifest/release.yaml" > "$work/release.yaml"
[ "$n" -gt 0 ] || fail "release.yaml has no service placeholders to stand in for"

out="$work/stacks"
CHARTS="$charts" RELEASE="$work/release.yaml" HELM="$helm" OUT="$out" bash "$here/render.sh" > "$work/render.log"
for st in sneakers sneakers-mcp sneakers-import edge; do
  [ -s "$out/$st/$st.yaml" ] || fail "no $st stack"
done
echo "ok: rendered $(cd "$out" && echo */ | tr -d /)"

# Complete: every component pinned, every service run.
go run "$root/build/tools/bundle" images --release "$work/release.yaml" > "$work/pinned"
for c in $(sed -n 's/.*image: \([a-z0-9._-]*\)}.*/\1/p' "$here/product.yaml"); do
  grep -q "/$c sha256:" "$work/pinned" || fail "the component $c isn't pinned in release.yaml"
done
# The migrate image runs as the import's Job (import/job.yaml), not in a stack.
go run "$root/build/tools/bundle" sources --release "$charts/manifest/release.yaml" | grep -v '^migrate ' | while read -r _ image _; do
  grep -qh "image: $image@sha256:" "$out"/*/*.yaml || fail "no stack runs $image"
done
grep -q '^ghcr.io/sneakers-pam/sneakers-migrate sha256:' "$work/pinned" || fail "the migrate Job image isn't pinned"
grep -q 'sneakers/sneakers-migrate' "$out/sneakers/sneakers.yaml" || fail "the vault and audit don't list the migrate caller"
echo "ok: every component is pinned, every service image runs in a stack, and the import's image and caller are in place"

# The import's Job reads only box secrets product.yaml declares, key and all
# (no stack carries it, so build/tools/stack never sees it).
job="$here/import-job.yaml"
refs="$(awk '/secretKeyRef:/ { r = 1; next } r && /name:/ { n = $2 } r && /key:/ { print n, $2; r = 0 }' "$job")"
[ -n "$refs" ] || fail "the import Job reads no Secret"
while read -r name key; do
  awk -v s="sneakers/$name" -v k="$key" '
    /^  - secret: / { in_s = ($3 == s) }
    in_s && $0 ~ "\\{key: " k "," { found = 1 }
    END { exit !found }' "$here/product.yaml" || fail "the import Job reads $key from the Secret $name, which product.yaml doesn't declare as a box secret key"
done <<<"$refs"
echo "ok: the import Job reads only box secrets"

# The product's About: the release's version, and the box's placeholders
# for its Base OS, Base Web and FQDN, each one product.yaml declares.
# The chart puts each service's settings in its ConfigMap, a "NAME: value" line each.
env_value() { sed -n "s/^ *$1: //p" "$out/sneakers/sneakers.yaml" | tr -d "\"'" | head -1; }
release_version="$(go run "$root/build/tools/bundle" version --release "$work/release.yaml")"
want=(
  "SNEAKERS_PRODUCT_VERSION $release_version"
  "SNEAKERS_APPLIANCE_VERSION baseos-version.invalid"      # scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
  "SNEAKERS_APPLIANCE_WEB_VERSION baseweb-version.invalid" # scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
  "SNEAKERS_APPLIANCE_FQDN sneakers.box.invalid"           # scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
)
for kv in "${want[@]}"; do
  read -r name value <<<"$kv"
  got="$(env_value "$name")"
  [ "$got" = "$value" ] || fail "the gateway's $name is \"$got\", want $value"
done
for ph in $(sed -n 's/^ *placeholder: \([a-z0-9.-]*\).*/\1/p' "$here/product.yaml"); do
  grep -qF "$ph" "$out/sneakers/sneakers.yaml" || fail "no stack carries the placeholder $ph"
done
echo "ok: the gateway gets the product version $release_version and the box's placeholders"

# Pinned by digest and never pulled.
if grep -h '^ *image: ' "$out"/*/*.yaml | grep -v '@sha256:[0-9a-f]\{64\}$' | grep -q .; then
  fail "an image isn't pinned by digest: $(grep -h '^ *image: ' "$out"/*/*.yaml | grep -v '@sha256:' | head -1)"
fi
if grep -h 'imagePullPolicy:' "$out"/sneakers*/*.yaml | grep -vq 'Never'; then
  fail "a container may pull its image"
fi
echo "ok: every image is pinned by digest and never pulled"

# No Secret value in any stack.
if grep -l '^kind: Secret$' "$out"/sneakers*/*.yaml; then fail "a stack carries a Secret"; fi
echo "ok: no stack carries a Secret"

# Nothing of a lab build.
lab='(^|[^A-Za-z])[Ll][Aa][Bb]([^A-Za-z]|$)|127\.0\.0\.1:5[0-9]{3}/|localhost:5000|LOG_LEVEL: (debug|trace)|LOG_FORMAT: console|DEV_QUICK_LOGIN: "?true|DEV_UI_ISSUE_COPY: "?true|ENVIRONMENT: (dev|development|test|lab)'
if grep -nE "$lab" "$out"/sneakers*/*.yaml "$here/values.yaml" "$here/values-mcp-on.yaml" "$work/release.yaml" > "$work/lab.txt"; then
  head -5 "$work/lab.txt" >&2
  fail "a lab value in the production stacks"
fi
if grep -h '^ *image: ' "$out"/*/*.yaml | grep -vE 'image: (ghcr\.io|docker\.io|quay\.io)/' | grep -q .; then
  fail "an image from a registry that isn't ghcr.io, docker.io or quay.io"
fi
echo "ok: no lab value"

# The OAuth issuer (Ory Hydra) is https://<fqdn>/oauth, on the box's one
# name and certificate: the edge routes /oauth/ to Hydra's public port and
# strips the prefix, Hydra's discovery and endpoints carry it, and the
# gateway checks tokens against it. No hydra.<fqdn> address is left.
mcp="$out/sneakers-mcp/sneakers-mcp.yaml"
host='sneakers.box.invalid'  # scrub:allow=fqdn -- the reserved .invalid placeholder
if grep -nE "hydra\.$host|hydra\.\{\{" "$out"/*/*.yaml "$here/values.yaml" "$here/values-mcp-on.yaml"; then fail "a hydra.<fqdn> address is left"; fi
mkdir -p "$work/mcpdocs"
awk -v d="$work/mcpdocs" 'BEGIN{n=0; f=d"/0.yaml"} /^---$/{n++; f=d"/"n".yaml"; next} {print > f}' "$mcp"
ing="" hcm="" sw=""
for f in "$work"/mcpdocs/*.yaml; do
  grep -q '^kind: Ingress$' "$f" && grep -q 'name: sneakers-hydra-public$' "$f" && ing="$f"
  grep -q '^kind: ConfigMap$' "$f" && grep -q '^    name: sneakers-hydra$' "$f" && hcm="$f"
  grep -q '^kind: ConfigMap$' "$f" && grep -q '^    name: sneakers-mcp-switch$' "$f" && sw="$f"
done
[ -n "$ing" ] || fail "no Ingress for Hydra's public port in the sneakers-mcp stack"
# Only Hydra's own paths: the staff app serves the MCP consent page at
# /oauth/consent (the gateway's /oauth2/authorize sends the browser there),
# so a route on all of /oauth/ would hide it.
for p in /oauth/.well-known/ /oauth/oauth2/ /oauth/userinfo; do
  grep -q "path: $p\$" "$ing" || fail "Hydra's Ingress has no $p route: $(grep 'path:' "$ing" | tr -s ' ')"
done
if grep -h 'path: ' "$out"/*/*.yaml | grep -qE 'path: /oauth/?$'; then fail "a route takes all of /oauth/, which hides the staff app's /oauth/consent"; fi
grep -q 'router.middlewares: .*oauth-prefix@file' "$ing" || fail "Hydra's Ingress doesn't strip /oauth"
grep -q 'router.middlewares: .*box-page@file' "$ing" || fail "Hydra's Ingress lacks the box-state page"
[ -n "$hcm" ] || fail "no Hydra config"
grep -q "issuer: https://$host/oauth\$" "$hcm" || fail "Hydra's issuer isn't https://<fqdn>/oauth: $(grep -m1 'issuer:' "$hcm")"
grep -q "public: https://$host/oauth/\$" "$hcm" || fail "Hydra's public URL isn't https://<fqdn>/oauth/"
[ -n "$sw" ] || fail "no sneakers-mcp-switch ConfigMap"
grep -q "HYDRA_ISSUER: https://$host/oauth\$" "$sw" || fail "the gateway doesn't check https://<fqdn>/oauth: $(grep HYDRA_ISSUER "$sw")"
grep -q "OAUTH_PUBLIC_URL: https://$host\$" "$sw" || fail "the root authorization server moved: $(grep OAUTH_PUBLIC_URL "$sw")"
awk -v RS='---\n' '/kind: NetworkPolicy/ && /\n    name: sneakers-hydra\n/' "$mcp" | grep -q 'cidr: 198.18.0.1/32' || fail "Hydra's public port doesn't take the edge"
grep -A3 'oauth-prefix:' "$out/edge/edge.yaml" | grep -q 'prefixes: \["/oauth"\]' || fail "the edge has no oauth-prefix middleware"
echo "ok: the OAuth issuer is https://<fqdn>/oauth, behind the edge's /oauth/ routes, and /oauth/consent stays the staff app's"

# The mail relay comes only from the box (the Email page): the identity
# service, which sends the product's mail, loads the sneakers-email
# ConfigMap and reads SMTP_PASS from the sneakers-email Secret, both of
# which the box writes (product.yaml box_settings and box_secrets). No
# stack carries an SMTP value of its own, and no ConfigMap the password.
mkdir -p "$work/docs"
awk -v d="$work/docs" 'BEGIN{n=0; f=d"/0.yaml"} /^---$/{n++; f=d"/"n".yaml"; next} {print > f}' "$out"/sneakers*/*.yaml
ident=""
for f in "$work"/docs/*.yaml; do
  if grep -q '^kind: ConfigMap$' "$f"; then
    if grep -qE 'SMTP_PASS|smtpConnectionURI|smtps?://' "$f"; then fail "a ConfigMap carries the relay password or URI: $(grep -m1 -E '^    name:' "$f")"; fi
    if grep -q '^    name: sneakers-identity$' "$f" && grep -q 'SMTP_' "$f"; then fail "the identity service's own ConfigMap sets SMTP values: $(grep SMTP_ "$f" | head -2)"; fi
  fi
  if grep -q '^kind: Deployment$' "$f" && grep -q '^    name: sneakers-identity$' "$f"; then ident="$f"; fi
done
[ -n "$ident" ] || fail "no sneakers-identity Deployment"
grep -A1 'configMapRef:' "$ident" | grep -q 'name: sneakers-email' || fail "the identity service doesn't load the sneakers-email ConfigMap"
grep -A4 -- '- name: SMTP_PASS' "$ident" | grep -q 'name: sneakers-email' || fail "the identity service doesn't read SMTP_PASS from the sneakers-email Secret"
if grep -nE 'smtp\.example\.org|smtp-[a-z]+\.box\.invalid' "$out"/*/*.yaml "$here/values.yaml" "$here/product.yaml"; then fail "an SMTP placeholder or example relay is left"; fi
echo "ok: the mail relay comes only from the box, and the password never from a ConfigMap"

# Refusals.
if CHARTS="$charts" RELEASE="$work/release.yaml" HELM="$helm" OUT="$out" bash "$here/render.sh" > /dev/null 2>&1; then
  fail "rendered into a non-empty OUT"
fi
cat > "$work/lab-secret.yaml" <<'YAML'
vault:
  secretEnv:
    VAULT_ROOT_KEK:
      secretName: sneakers-lab-secrets
YAML
if CHARTS="$charts" RELEASE="$work/release.yaml" HELM="$helm" EXTRA_VALUES="$work/lab-secret.yaml" OUT="$work/refused" bash "$here/render.sh" > "$work/refused.log" 2>&1; then
  fail "rendered a workload reading a Secret no box makes"
fi
grep -q 'sneakers-lab-secrets' "$work/refused.log" || fail "the refusal doesn't name the Secret: $(tail -2 "$work/refused.log")"
echo "ok: refused a non-empty OUT and a Secret no box makes"
