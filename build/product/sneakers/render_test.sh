#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The production product bundle's stacks, rendered by render.sh from
# sneakers-release's charts, are complete and carry nothing of a lab build:
#
#   - every component product.yaml names is pinned in release.yaml, every
#     service image release.yaml pins runs in a stack, the migrate Job image
#     is pinned and the vault and audit list the migrate caller;
#   - every container runs an image pinned by digest, never pulled;
#   - no stack carries a Secret (each box makes its own), and every
#     Secret a workload reads is a box secret product.yaml declares
#     (build/tools/stack refuses otherwise);
#   - no lab value: no lab registry or host, no debug or console logging, no
#     dev-only switch, no "lab" in a name or value;
#   - every workload is in its phase's own stack, labelled with the phase,
#     and the always-on stack holds none;
#   - every wait-phase init container runs with arguments the release's own
#     sneakers-migrate wait takes, and exits 0 once its DNS and targets
#     answer (the DNS-only waits too);
#   - the gateway's OAuth routes have OAUTH_PUBLIC_URL with the MCP off and
#     on, and the MCP server, Hydra and their routes stay behind the switch;
#   - render.sh refuses a non-empty OUT, and a values overlay that brings
#     a Secret no box makes.
#
# CHARTS is a sneakers-release checkout; without it the test fetches the
# commit build/release/pins.env pins (or main while that's empty), and
# MIGRATE_SRC is one at the migrate image's commit (fetched without it). The
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

# Phased: each phase's own stack holds its workloads, labelled with the
# phase on the workload and its pods, and the always-on stack holds none
# (build/tools/stack refuses a workload no phase names).
for st in $(sed -n 's/^    stack: \(sneakers-[a-z-]*\)$/\1/p' "$here/product.yaml"); do
  [ -s "$out/$st/$st.yaml" ] || fail "no phase stack $st"
  grep -q '^kind: \(Deployment\|StatefulSet\)$' "$out/$st/$st.yaml" || fail "the phase stack $st holds no workload"
  [ "$(grep -c 'sneakers-appliance/phase-order:' "$out/$st/$st.yaml")" -ge 2 ] || fail "the phase stack $st's workloads carry no phase labels"
done
if grep -q '^kind: \(Deployment\|StatefulSet\|DaemonSet\)$' "$out/sneakers/sneakers.yaml"; then
  fail "the always-on stack holds a workload: every workload starts in its phase"
fi
grep -q 'sneakers-appliance/phase: front' "$out/sneakers-mcp/sneakers-mcp.yaml" || fail "the MCP switch's workloads aren't in the front phase"
# Each phased workload waits for the cluster's DNS and its needs first,
# with the release's migrate image.
migrate_ref="$(go run "$root/build/tools/bundle" images --release "$work/release.yaml" | awk '$1 ~ /sneakers-migrate$/ { print $1 "@" $2 }')"
for st in $(sed -n 's/^    stack: \(sneakers-[a-z-]*\)$/\1/p' "$here/product.yaml") sneakers-mcp; do
  workloads="$(grep -c '^kind: \(Deployment\|StatefulSet\)$' "$out/$st/$st.yaml")"
  waits="$(grep -c -- '- name: wait-phase$\|^ *name: wait-phase$' "$out/$st/$st.yaml")"
  [ "$waits" -eq "$workloads" ] || fail "the phase stack $st has $workloads workloads and $waits waits"
  grep -q "image: $migrate_ref\$" "$out/$st/$st.yaml" || fail "the phase stack $st's waits don't run $migrate_ref"
done
grep -q -- '--tcp' "$out/sneakers-front/sneakers-front.yaml" || fail "the gateway waits for none of the services"
echo "ok: every workload is in its phase's stack and waits for its needs"

# The waits run: each wait-phase init container's arguments, in every
# stack, are ones the release's own `wait` takes. sneakers-migrate is built
# from the commit release.yaml pins for its image (MIGRATE_SRC, a
# sneakers-release checkout at that commit, or fetched), and each wait runs
# twice: as rendered, where the cluster's DNS never resolves, so it must
# still be retrying after 5 s rather than refusing its arguments; and with
# its DNS name and every target pointed at this machine, where it must
# exit 0. A DNS-only wait (the database's, the cache's) is one of them.
migrate_commit="$(go run "$root/build/tools/bundle" sources --release "$work/release.yaml" | awk '$1 == "migrate" { print $5 }')"
[ -n "$migrate_commit" ] || fail "release.yaml pins no commit for the migrate image"
msrc="${MIGRATE_SRC:-}"
if [ -z "$msrc" ]; then
  msrc="$work/migrate-src"
  git init -q "$msrc"
  git -C "$msrc" fetch -q --depth 1 "https://github.com/Sneakers-PAM/sneakers-release.git" "$migrate_commit"
  git -C "$msrc" checkout -q FETCH_HEAD
fi
[ "$(git -C "$msrc" rev-parse HEAD)" = "$migrate_commit" ] || fail "MIGRATE_SRC isn't at the migrate image's commit $migrate_commit"
(cd "$msrc" && CGO_ENABLED=0 go build -o "$work/sneakers-migrate" ./migrate/cmd/sneakers-migrate)
# One line per wait: the stack, the workload, then its arguments.
awk '
  FNR == 1 { st = FILENAME; sub(/.*\//, "", st); sub(/\.yaml$/, "", st); kind = ""; name = "" }
  /^kind: / { kind = $2; name = "" }
  /^    name: / && name == "" { name = $2 }
  collecting && /^ *- [^ ]+$/ { a = a " " $2; next }
  collecting { if (a ~ /^ wait /) print st, kind "/" name a; collecting = 0 }
  /^ *- args:$/ { collecting = 1; a = "" }
' "$out"/*/*.yaml > "$work/waits"
nwaits="$(wc -l < "$work/waits")"
nwant="$(cat "$out"/*/*.yaml | grep -c -- '^ *name: wait-phase$\|^ *- name: wait-phase$')"
[ "$nwaits" -gt 0 ] && [ "$nwaits" -eq "$nwant" ] || fail "found $nwaits wait argument lists for $nwant wait-phase init containers"
grep -q '^sneakers-data StatefulSet/sneakers-postgres wait --dns [^ ]* --every 2s$' "$work/waits" || fail "the database's wait isn't the DNS-only one: $(grep sneakers-postgres "$work/waits" || echo none)"
# A local TCP listener for the targets; it stops once this script exits.
python3 -c '
import os, socket
parent = os.getppid()
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(64); s.settimeout(1)
print(s.getsockname()[1], flush=True)
while os.getppid() == parent:
    try:
        c, _ = s.accept(); c.close()
    except socket.timeout:
        pass
' < /dev/null > "$work/port" 2> /dev/null &
listener=$!
for _ in $(seq 50); do [ -s "$work/port" ] && break; sleep 0.1; done
port="$(cat "$work/port")"
[ -n "$port" ] || fail "no local listener for the waits"
while read -r st wl args; do
  read -ra a <<<"$args"
  rc=0
  timeout 5 "$work/sneakers-migrate" "${a[@]}" < /dev/null > "$work/wait.log" 2>&1 || rc=$?
  [ "$rc" -eq 124 ] || fail "$st $wl: the release's wait exited $rc on its rendered arguments ($args): $(tail -1 "$work/wait.log")"
  local_args=()
  for ((i = 0; i < ${#a[@]}; i++)); do
    case "${a[$i]}" in
      --dns) local_args+=(--dns localhost); i=$((i + 1)) ;;
      --tcp) local_args+=(--tcp "127.0.0.1:$port"); i=$((i + 1)) ;;
      *) local_args+=("${a[$i]}") ;;
    esac
  done
  rc=0
  timeout 10 "$work/sneakers-migrate" "${local_args[@]}" < /dev/null > "$work/wait.log" 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || fail "$st $wl: the release's wait exited $rc once its DNS and targets answered (${local_args[*]}): $(tail -1 "$work/wait.log")"
done < "$work/waits"
kill "$listener" 2>/dev/null || true
echo "ok: the release's wait (sneakers-migrate at ${migrate_commit:0:7}) takes all $nwaits waits and exits 0 once each one's DNS and targets answer"

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
grep -q 'sneakers/sneakers-migrate' "$out/sneakers-identity/sneakers-identity.yaml" || fail "the vault doesn't list the migrate caller"
grep -q 'sneakers/sneakers-migrate' "$out/sneakers-services/sneakers-services.yaml" || fail "the audit service doesn't list the migrate caller"
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
awk -v RS='---\n' '/kind: NetworkPolicy/ && /\n    name: sneakers-hydra\n/' "$mcp" | grep -q 'cidr: 198.18.0.1/32' || fail "Hydra's public port doesn't take the edge"
grep -A3 'oauth-prefix:' "$out/edge/edge.yaml" | grep -q 'prefixes: \["/oauth"\]' || fail "the edge has no oauth-prefix middleware"
# The MCP server's protected-resource metadata (RFC 9728) names the
# resource at the box's own name and its authorization server, so an OAuth
# MCP client finds sign-in from /.well-known/oauth-protected-resource; the
# server serves none without MCP_RESOURCE_URL.
mcm=""
for f in "$work"/mcpdocs/*.yaml; do
  grep -q '^kind: ConfigMap$' "$f" && grep -q '^    name: sneakers-mcp$' "$f" && mcm="$f"
done
[ -n "$mcm" ] || fail "no sneakers-mcp ConfigMap"
grep -q "MCP_RESOURCE_URL: https://$host/mcp\$" "$mcm" || fail "the MCP server's resource isn't https://<fqdn>/mcp: $(grep MCP_RESOURCE_URL "$mcm" || echo unset)"
grep -q "MCP_AUTHORIZATION_SERVER: https://$host\$" "$mcm" || fail "the MCP server's authorization server isn't https://<fqdn>: $(grep MCP_AUTHORIZATION_SERVER "$mcm" || echo unset)"
awk -v RS='---\n' '/kind: Ingress/ && /\n    name: sneakers-mcp\n/' "$mcp" | grep -q 'path: /.well-known/oauth-protected-resource$' || fail "the edge doesn't route /.well-known/oauth-protected-resource to the MCP server"
echo "ok: the OAuth issuer is https://<fqdn>/oauth, behind the edge's /oauth/ routes, and /oauth/consent stays the staff app's"
echo "ok: the MCP server's protected-resource metadata names https://<fqdn>/mcp and https://<fqdn>"

# The command-line sign-in (sneakers-put login, sneakers-run login) is the
# gateway's own authorization server, which mounts only with OAUTH_PUBLIC_URL
# set, so it's in the base values: the same with the MCP off and on, and never
# one of the settings the switch's ConfigMap changes.
got="$(env_value OAUTH_PUBLIC_URL)"
[ "$got" = "https://$host" ] || fail "with the MCP off, the gateway's OAUTH_PUBLIC_URL is \"$got\", want https://$host"
if grep -q 'OAUTH_PUBLIC_URL' "$sw"; then fail "the MCP switch changes the gateway's OAUTH_PUBLIC_URL: $(grep OAUTH_PUBLIC_URL "$sw")"; fi
# With the MCP off the product routes those paths and none of the MCP's: the
# MCP server and Hydra's issuer stay in the switch's stack. HYDRA_ENABLED stays
# there too, since the gateway's readiness needs Hydra once it's true.
always="$(for f in "$out"/sneakers*/*.yaml; do [ "$f" = "$mcp" ] || cat "$f"; done)"
for p in /oauth2 /.well-known/oauth-authorization-server; do
  grep -q "path: $p\$" <<<"$always" || fail "with the MCP off, no route takes $p"
done
if grep -E 'path: (/mcp|/oauth/|/\.well-known/oauth-protected-resource)' <<<"$always"; then fail "an MCP or Hydra route runs with the MCP off"; fi
for kv in "MCP_ENABLED false" "HYDRA_ENABLED false" "HYDRA_ISSUER" "MCP_HEALTH_URL"; do
  read -r name value <<<"$kv"
  got="$(env_value "$name")"
  [ "$got" = "${value:-}" ] || fail "with the MCP off, the gateway's $name is \"$got\", want \"${value:-}\""
done
grep -qE "HYDRA_ENABLED: [\"']?true" "$sw" || fail "the MCP switch doesn't turn Hydra on: $(grep HYDRA_ENABLED "$sw" || echo unset)"
grep -qE "MCP_ENABLED: [\"']?true" "$sw" || fail "the MCP switch doesn't turn the MCP on: $(grep MCP_ENABLED "$sw" || echo unset)"
echo "ok: the gateway's OAuth routes have their public address with the MCP off and on, and the rest stays behind the switch"

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
